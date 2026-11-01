"""Webhook subscriptions (tenant-scoped). Secrets are encrypted at rest and shown exactly once, on creation/rotation."""
from __future__ import annotations
import re
import secrets
import uuid
from typing import Any, Dict, List, Optional

from psycopg.types.json import Jsonb

from app.core import config as cfg
from app.core import crypto
from app.core import db as dbmod
from app.core import tenancy, urlcheck

EVENTS = ("audit.completed", "finding.new_critical_high", "job.failed", "ping")
FORMATS = ("json", "slack", "teams", "cef", "jira", "servicenow")
_BAD_HEADERS = {"host", "content-length", "content-type", "transfer-encoding", "connection", "user-agent",
                "x-signature-256", "x-timestamp", "x-event", "x-delivery-id"}
_PUB = ("webhook_id, name, url, events, format, enabled, consecutive_failures, disabled_reason, last_status, created_by, "
        "(auth_header_enc IS NOT NULL) AS has_auth_header, "
        "extract(epoch from last_delivery_at) AS last_delivery_at, extract(epoch from created_at) AS created_at")


class WebhookError(ValueError):
    pass


def _rows(cur) -> List[Dict[str, Any]]:
    cols = [d[0] for d in cur.description]
    out = []
    for r in cur.fetchall():
        d = dict(zip(cols, r))
        for k in ("last_delivery_at", "created_at"):
            d[k] = float(d[k]) if d.get(k) is not None else None
        out.append(d)
    return out


def _validate(url: str, events: List[str], fmt: str) -> List[str]:
    try:
        urlcheck.validate(url)
    except urlcheck.UnsafeURL as e:
        raise WebhookError(str(e))
    ev = sorted({e.strip() for e in events if e.strip()})
    bad = [e for e in ev if e not in EVENTS]
    if not ev or bad:
        raise WebhookError(f"events must be a non-empty subset of {list(EVENTS)}")
    if fmt not in FORMATS:
        raise WebhookError(f"format must be one of {list(FORMATS)}")
    return ev


def validate_auth_header(value: str) -> str:
    """'Header-Name: token' -> normalised string. Rejects CR/LF (header injection) and headers we set ourselves."""
    v = (value or "").strip()
    if len(v) > 2000 or "\r" in v or "\n" in v or "\x00" in v:
        raise WebhookError("auth header must be a single line of at most 2000 characters")
    name, sep, token = v.partition(":")
    name, token = name.strip(), token.strip()
    if not sep or not token or not re.fullmatch(r"[A-Za-z0-9-]{1,64}", name):
        raise WebhookError("auth header must look like 'Authorization: Bearer <token>'")
    if name.lower() in _BAD_HEADERS:
        raise WebhookError(f"header {name!r} is set by the platform and cannot be overridden")
    return f"{name}: {token}"


def create(name: str, url: str, events: List[str], fmt: str, created_by: Optional[str],
           auth_header: Optional[str] = None) -> Dict[str, Any]:
    ev = _validate(url, events, fmt)
    auth_enc = crypto.encrypt(validate_auth_header(auth_header)) if auth_header else None
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("SELECT count(*) FROM webhooks WHERE org_id=%s", (tenancy.current_org(),))
        if cur.fetchone()[0] >= cfg.WEBHOOK_MAX_PER_ORG:
            raise WebhookError(f"webhook limit reached ({cfg.WEBHOOK_MAX_PER_ORG})")
        wid, secret = "WHK-" + uuid.uuid4().hex[:10].upper(), "whsec_" + secrets.token_urlsafe(32)
        cur.execute("INSERT INTO webhooks (webhook_id, org_id, name, url, secret_enc, events, format, created_by, auth_header_enc) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (wid, tenancy.current_org(), name.strip()[:200], url, crypto.encrypt(secret), Jsonb(ev), fmt, created_by, auth_enc))
    out = get(wid) or {}
    out["secret"] = secret                      # the only time it is ever returned
    return out


def get(webhook_id: str) -> Optional[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(f"SELECT {_PUB} FROM webhooks WHERE webhook_id=%s AND org_id=%s", (webhook_id, tenancy.current_org()))
        rows = _rows(cur)
        return rows[0] if rows else None


def list_all() -> List[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(f"SELECT {_PUB} FROM webhooks WHERE org_id=%s ORDER BY created_at DESC", (tenancy.current_org(),))
        return _rows(cur)


def update(webhook_id: str, *, name: Optional[str] = None, url: Optional[str] = None, events: Optional[List[str]] = None,
           fmt: Optional[str] = None, enabled: Optional[bool] = None,
           auth_header: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """auth_header: None = leave unchanged, "" = clear, otherwise replace."""
    cur_row = get(webhook_id)
    if not cur_row:
        return None
    new_url = url if url is not None else cur_row["url"]
    new_events = events if events is not None else cur_row["events"]
    new_fmt = fmt if fmt is not None else cur_row["format"]
    ev = _validate(new_url, new_events, new_fmt)
    sets = ["url=%s", "events=%s", "format=%s"]
    vals: list = [new_url, Jsonb(ev), new_fmt]
    if name is not None:
        sets.append("name=%s")
        vals.append(name.strip()[:200])
    if auth_header is not None:
        sets.append("auth_header_enc=%s")
        vals.append(crypto.encrypt(validate_auth_header(auth_header)) if auth_header.strip() else None)
    if enabled is not None:
        sets.append("enabled=%s")
        vals.append(enabled)
        if enabled:                              # re-enabling clears the auto-disable state
            sets += ["consecutive_failures=0", "disabled_reason=NULL"]
    with dbmod.get_conn() as conn:
        conn.cursor().execute(f"UPDATE webhooks SET {', '.join(sets)} WHERE webhook_id=%s AND org_id=%s",  # type: ignore[attr-defined]
                              vals + [webhook_id, tenancy.current_org()])
    return get(webhook_id)


def rotate_secret(webhook_id: str) -> Optional[str]:
    secret = "whsec_" + secrets.token_urlsafe(32)
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("UPDATE webhooks SET secret_enc=%s WHERE webhook_id=%s AND org_id=%s RETURNING webhook_id",
                    (crypto.encrypt(secret), webhook_id, tenancy.current_org()))
        return secret if cur.fetchone() else None


def delete(webhook_id: str) -> bool:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("DELETE FROM webhooks WHERE webhook_id=%s AND org_id=%s", (webhook_id, tenancy.current_org()))
        return cur.rowcount > 0


def matching(event: str) -> List[Dict[str, Any]]:
    """Enabled hooks of the CURRENT org subscribed to `event`."""
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(f"SELECT {_PUB} FROM webhooks WHERE org_id=%s AND enabled AND events @> %s",
                    (tenancy.current_org(), Jsonb([event])))
        return _rows(cur)


def deliveries(webhook_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("SELECT delivery_id, event, status, http_status, error, attempt, duration_ms, "
                    "extract(epoch from created_at) AS created_at FROM webhook_deliveries "
                    "WHERE webhook_id=%s AND org_id=%s ORDER BY created_at DESC LIMIT %s",
                    (webhook_id, tenancy.current_org(), limit))
        rows = _rows(cur)
    for r in rows:
        r["created_at"] = float(r["created_at"])
    return rows


# ------------------------------------------------------------- delivery side (worker; org already bound)
def load_for_delivery(webhook_id: str) -> Optional[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("SELECT webhook_id, url, secret_enc, format, enabled, auth_header_enc FROM webhooks WHERE webhook_id=%s AND org_id=%s",
                    (webhook_id, tenancy.current_org()))
        r = cur.fetchone()
    if not r:
        return None
    return {"webhook_id": r[0], "url": r[1], "secret": crypto.decrypt(r[2]), "format": r[3], "enabled": r[4],
            "auth_header": crypto.decrypt(r[5]) if r[5] else None}


def log_delivery(webhook_id: str, event: str, ok: bool, http_status: Optional[int], error: Optional[str],
                 attempt: int, duration_ms: int) -> None:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("INSERT INTO webhook_deliveries (delivery_id, webhook_id, org_id, event, status, http_status, error, attempt, duration_ms) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    ("DLV-" + uuid.uuid4().hex[:12].upper(), webhook_id, tenancy.current_org(), event,
                     "SUCCESS" if ok else "FAILED", http_status, (error or "")[:500] or None, attempt, duration_ms))
        if ok:
            cur.execute("UPDATE webhooks SET consecutive_failures=0, last_status='SUCCESS', last_delivery_at=now() WHERE webhook_id=%s",
                        (webhook_id,))
        else:
            cur.execute(
                "UPDATE webhooks SET consecutive_failures=consecutive_failures+1, last_status='FAILED', last_delivery_at=now(), "
                "enabled = CASE WHEN consecutive_failures+1 >= %s THEN false ELSE enabled END, "
                "disabled_reason = CASE WHEN consecutive_failures+1 >= %s THEN 'disabled after repeated delivery failures' "
                "                       ELSE disabled_reason END WHERE webhook_id=%s", (cfg.WEBHOOK_DISABLE_AFTER, cfg.WEBHOOK_DISABLE_AFTER, webhook_id))
