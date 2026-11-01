"""Domain events -> signed webhook deliveries (via the job queue, so they get retries and backoff).

Each delivery is signed so the receiver can verify authenticity and reject replays:

    X-Signature-256: sha256=<hex HMAC-SHA256(secret, f"{timestamp}.{raw_body}")>
    X-Timestamp:     unix seconds   (reject if older than a few minutes)
    X-Event / X-Delivery-Id

Payloads carry summaries and ids only - never configuration text, secrets or evidence lines.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import logging
import time
import uuid
from typing import Any, Dict, Optional

import httpx

from app.core import config as cfg
from app.core import jobs, urlcheck, webhooks
from app.services import webhook_formats as wf

log = logging.getLogger("sih26155")


def sign(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def verify(secret: str, timestamp: str, body: bytes, signature: str, tolerance_s: int = 300) -> bool:
    """Reference verifier (documented for receivers; used in tests)."""
    try:
        if abs(time.time() - int(timestamp)) > tolerance_s:
            return False
    except ValueError:
        return False
    return hmac.compare_digest(sign(secret, timestamp, body), signature)


def _headline(event: str, d: Dict[str, Any]) -> str:
    asset = d.get("asset_name") or d.get("asset_id") or "an asset"
    if event == "audit.completed":
        return (f"Audit completed for {asset}: score {d.get('compliance_score')}%, "
                f"{d.get('failed', 0)} failed" + (f", {d['changes']['new']} new / {d['changes']['resolved']} resolved"
                                                  if d.get("changes", {}).get("new") is not None else ""))
    if event == "finding.new_critical_high":
        return f"{d.get('changes', {}).get('new_critical_high', 0)} new critical/high finding(s) on {asset} (score {d.get('compliance_score')}%)"
    if event == "job.failed":
        return f"Background job {d.get('job_id')} ({d.get('kind')}) failed: {d.get('error', '')[:200]}"
    return "Webhook test (ping) from the Network Security Compliance Auditor"


def render(fmt: str, event: str, envelope: Dict[str, Any]) -> Dict[str, Any]:
    text = _headline(event, envelope["data"])
    if fmt == "slack":
        return {"text": text}
    if fmt == "teams":
        return {"@type": "MessageCard", "@context": "https://schema.org/extensions", "summary": text, "title": text}
    if fmt == "jira":
        return wf.render_jira(event, envelope, text)
    if fmt == "servicenow":
        return wf.render_servicenow(event, envelope, text)
    return envelope


def encode_body(fmt: str, event: str, envelope: Dict[str, Any]) -> tuple:
    """(body bytes, content type). CEF is one text line; every other format is compact JSON."""
    if fmt == "cef":
        return wf.render_cef(event, envelope, _headline(event, envelope["data"])).encode("utf-8"), "text/plain; charset=utf-8"
    return json.dumps(render(fmt, event, envelope), separators=(",", ":"), sort_keys=True).encode(), "application/json"


def emit(event: str, data: Dict[str, Any]) -> int:
    """Queue a delivery for every matching webhook of the current org. Never raises into the caller."""
    n = 0
    try:
        for h in webhooks.matching(event):
            jobs.enqueue("webhook", {"webhook_id": h["webhook_id"], "event": event, "data": data}, created_by="events", max_attempts=5)
            n += 1
    except Exception as e:  # noqa: BLE001 - notifications are best-effort; they must not break the audit pipeline
        log.error("emit(%s) failed: %s", event, e)
    return n


def _post_pinned(targets, body: bytes, headers: Dict[str, str]):
    """POST to the first validated address that accepts a connection. No redirects are followed (a 3xx would
    re-point us at an address nobody validated), the original name travels in Host + TLS SNI."""
    last: Optional[Exception] = None
    with httpx.Client(timeout=cfg.WEBHOOK_TIMEOUT_S, follow_redirects=False) as client:
        for t in targets:
            ext = {"sni_hostname": t.sni_hostname} if t.sni_hostname else {}
            try:
                return client.post(t.url, content=body, headers={**headers, **t.headers}, extensions=ext)
            except httpx.ConnectError as e:                 # try the next validated address
                last = e
    assert last is not None
    raise last


def deliver(job: Dict[str, Any]) -> Dict[str, Any]:
    """Job handler (org already bound by the worker). Retries by raising; permanent problems raise PermanentJobError."""
    from app.services.job_handlers import PermanentJobError
    p = job["payload"]
    hook = webhooks.load_for_delivery(str(p.get("webhook_id", "")))
    if not hook:
        raise PermanentJobError("webhook was deleted")
    if not hook["enabled"]:
        raise PermanentJobError("webhook is disabled")
    event = str(p.get("event"))
    try:
        targets = urlcheck.pin(hook["url"])         # resolve + validate ONCE; we connect to the validated address only
    except urlcheck.UnsafeURL as e:
        webhooks.log_delivery(hook["webhook_id"], event, False, None, f"blocked: {e}", job["attempts"], 0)
        raise PermanentJobError(f"destination blocked: {e}")
    delivery_id = "dlv_" + uuid.uuid4().hex[:16]
    envelope = {"id": delivery_id, "event": event, "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "org_id": job["org_id"], "data": p.get("data") or {}}
    body, ctype = encode_body(hook["format"], event, envelope)
    ts = str(int(time.time()))
    headers = {"Content-Type": ctype, "User-Agent": "NSCA-Webhook/1.0", "X-Event": event,
               "X-Delivery-Id": delivery_id, "X-Timestamp": ts, "X-Signature-256": sign(hook["secret"], ts, body)}
    auth = hook.get("auth_header")
    if auth:                                         # user-supplied credential for the receiver (Jira / ServiceNow); never logged
        hname, _, hval = auth.partition(":")
        headers[hname.strip()] = hval.strip()
    t0 = time.time()
    try:
        r = _post_pinned(targets, body, headers)
    except (httpx.HTTPError, ValueError) as e:
        err = f"{type(e).__name__}: {e}"
        if auth:
            err = err.replace(auth.partition(":")[2].strip(), "***") if auth.partition(":")[2].strip() else err
        webhooks.log_delivery(hook["webhook_id"], event, False, None, err, job["attempts"], int((time.time() - t0) * 1000))
        raise RuntimeError(f"delivery failed: {type(e).__name__}")
    ms = int((time.time() - t0) * 1000)
    if 200 <= r.status_code < 300:
        webhooks.log_delivery(hook["webhook_id"], event, True, r.status_code, None, job["attempts"], ms)
        return {"webhook_id": hook["webhook_id"], "http_status": r.status_code, "delivery_id": delivery_id}
    webhooks.log_delivery(hook["webhook_id"], event, False, r.status_code, f"HTTP {r.status_code}", job["attempts"], ms)
    if 400 <= r.status_code < 500 and r.status_code not in (408, 409, 425, 429):
        raise PermanentJobError(f"receiver rejected the delivery with HTTP {r.status_code}")   # a retry cannot fix a 4xx
    raise RuntimeError(f"HTTP {r.status_code}")
