"""Abuse limits: request-body size cap (enforced while streaming) and a per-org / per-user token bucket for the
expensive endpoints (audits, reports, uploads, AI suggestions, CVE sync).

Both are in-process: with several API workers the effective ceiling is multiplied by the worker count. They are a
fairness / cost control, not a substitute for edge rate limiting (nginx ``limit_req``) or WAF rules.
"""
from __future__ import annotations
import json
import re
import threading
import time
from typing import Any, Dict, List, Optional, Pattern, Tuple

from fastapi import Depends, HTTPException, Request

from app.core import config as cfg
from app.core import security as sec


# ------------------------------------------------------------------ request body cap
class _TooLarge(Exception):
    pass


class BodyLimitMiddleware:
    """Pure ASGI middleware: 413 as soon as a request body exceeds the cap - by Content-Length when declared,
    otherwise by counting bytes as they arrive (chunked uploads). Nothing is buffered here."""

    def __init__(self, app):
        self.app = app

    @staticmethod
    def _limit(headers: List[Tuple[bytes, bytes]]) -> int:
        for k, v in headers:
            if k == b"content-type" and v.lower().startswith(b"multipart/"):
                return cfg.MAX_UPLOAD_BODY_BYTES
        return cfg.MAX_JSON_BODY_BYTES

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        qs = scope.get("query_string") or b""
        if b"\x00" in qs or b"%00" in qs.lower() or "\x00" in str(scope.get("path", "")):
            await self._reject(send, 0, 400, "NUL bytes are not allowed in the URL")   # the driver would answer with HTTP 500
            return
        headers = scope.get("headers") or []
        limit = self._limit(headers)
        for k, v in headers:
            if k == b"content-length":
                try:
                    if int(v) > limit:
                        await self._reject(send, limit)
                        return
                except ValueError:
                    await self._reject(send, limit, 400, "Invalid Content-Length")
                    return
        seen = 0
        started = False
        replaced = False

        async def counting_receive():
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body") or b"")
                if seen > limit:
                    raise _TooLarge()
            return msg

        async def tracking_send(msg):
            nonlocal started, replaced
            if replaced:
                return
            if msg["type"] == "http.response.start":
                started = True
                if seen > limit:       # the framework swallowed our abort and answered 400/500: say 413 instead
                    replaced = True
                    await self._reject(send, limit)
                    return
            await send(msg)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _TooLarge:
            if not started:
                await self._reject(send, limit)
            return
        if seen > limit and not started:       # the app answered nothing at all: still refuse
            await self._reject(send, limit)

    @staticmethod
    async def _reject(send, limit: int, status: int = 413, message: Optional[str] = None) -> None:
        body = json.dumps({"success": False, "error": {
            "code": f"HTTP_{status}", "message": message or f"Request body too large (limit {limit} bytes)"}}).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                                (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})


# ------------------------------------------------------------------ expensive-endpoint token bucket
# (method, path regex, cost in tokens). First match wins.
_EXPENSIVE: List[Tuple[str, Pattern[str], int]] = [(m, re.compile(p), c) for m, p, c in [
    ("POST", r"^/api/v1/audits$", 1),
    ("POST", r"^/api/v1/configurations/(upload|bulk-upload)$", 1),
    ("POST", r"^/api/v1/configurations/[^/]+/parse$", 1),
    ("GET",  r"^/api/v1/configurations/[^/]+/unknowns$", 1),
    ("POST", r"^/api/v1/jobs/(audit|report)$", 1),
    ("POST", r"^/api/v1/jobs/bulk-audit$", 5),
    ("POST", r"^/api/v1/reports$", 2),
    ("GET",  r"^/api/v1/reports/(fleet|export/[^/]+|evidence/[^/]+)$", 2),
    ("POST", r"^/api/v1/training/[^/]+/suggest$", 2),
    ("POST", r"^/api/v1/remediation/[^/]+/apply$", 2),
    ("POST", r"^/api/v1/vulnerabilities/sync$", 10),
    ("POST", r"^/api/v1/analytics/fleet$", 2),
    ("POST", r"^/api/v1/schedules/[^/]+/run$", 1),
    ("POST", r"^/api/v1/detection/vendor$", 1),
    ("POST", r"^/api/v1/cloud/scans$", 2),
    ("POST", r"^/api/v1/cloud/schedules/[^/]+/run$", 2),
    ("GET",  r"^/api/v1/cloud/scans/[^/]+/export$", 2),
]]

_lock = threading.Lock()
_buckets: Dict[str, List[float]] = {}          # key -> [tokens, last refill (monotonic s)]
_MAX_KEYS = 20_000


def reset() -> None:
    with _lock:
        _buckets.clear()


def cost_of(method: str, path: str) -> int:
    for m, rx, c in _EXPENSIVE:
        if m == method and rx.match(path):
            return c
    return 0


def _take(key: str, cost: int, per_min: float, burst: float, now: float) -> float:
    """Take `cost` tokens; return 0.0 if allowed, else the seconds until enough tokens exist."""
    rate = per_min / 60.0
    b = _buckets.get(key)
    if b is None:
        if len(_buckets) >= _MAX_KEYS:                       # bound memory: drop buckets idle for 10+ minutes
            for k in [k for k, v in _buckets.items() if now - v[1] > 600]:
                _buckets.pop(k, None)
        b = _buckets[key] = [float(burst), now]
    b[0] = min(float(burst), b[0] + (now - b[1]) * rate)
    b[1] = now
    if b[0] >= cost:
        b[0] -= cost
        return 0.0
    return (cost - b[0]) / rate if rate > 0 else 60.0


def check(org: str, user_id: str, method: str, path: str, now: Optional[float] = None) -> float:
    """Seconds to wait (0.0 = allowed). Charges the org bucket and the user bucket."""
    per_min = cfg.RATE_LIMIT_EXPENSIVE_PER_MIN
    cost = cost_of(method, path)
    if per_min <= 0 or cost <= 0:
        return 0.0
    burst = max(float(cfg.RATE_LIMIT_EXPENSIVE_BURST), float(cost))
    t = time.monotonic() if now is None else now
    with _lock:
        wait = _take(f"org:{org}", cost, per_min, burst, t)
        if wait == 0.0:
            wait = _take(f"user:{user_id}", cost, per_min, burst, t)
        return wait


def rate_limit(request: Request, user: Dict[str, Any] = Depends(sec.require_user)) -> None:
    """Route dependency (applied to every /api/v1 router): 429 + Retry-After when the bucket is empty."""
    wait = check(str(user.get("org_id") or cfg.DEFAULT_ORG_ID), str(user.get("id") or ""),
                 request.method.upper(), request.url.path)
    if wait > 0:
        raise HTTPException(status_code=429, detail="Rate limit exceeded for this expensive operation; retry shortly",
                            headers={"Retry-After": str(max(1, int(wait + 0.999)))})
