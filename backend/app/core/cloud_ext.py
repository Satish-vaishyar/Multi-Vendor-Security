"""Cloud module extras (docs/CLOUD_MODULE_RTM.md S23): opt-in retained sources, recurring scans, links to existing webhooks and
assets. Own tables only (migrate_018.sql). Nothing here edits the existing schedules, webhooks or assets modules or tables: a
cloud schedule is a row in ``cloud_schedules`` run by ``app.cloud_scheduler``, and cloud events reach an existing webhook through
the existing ``webhook`` job kind. Every statement is parameterised and filtered by the caller's organisation."""
from __future__ import annotations
import base64
import hashlib
import uuid
from typing import Any, Dict, List, Optional

from app.core import crypto
from app.core import db as dbmod
from app.core import jobs, tenancy

CLOUD_EVENTS = ("cloud.scan.completed", "cloud.scan.failed")
LINKABLE_FORMATS = ("json",)           # the shared delivery code only knows how to word the existing event names
MAX_SOURCE_BYTES = 5 * 1024 * 1024
MAX_SOURCES_PER_ORG = 20
MAX_SCHEDULES_PER_ORG = 20
MIN_INTERVAL_MINUTES = 60
MAX_INTERVAL_MINUTES = 60 * 24 * 366
SOURCE_RETENTION_DAYS = 90


class ExtError(ValueError):
    pass


def _rows(cur) -> List[Dict[str, Any]]:
    cols = [d.name for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def _one(cur) -> Optional[Dict[str, Any]]:
    rows = _rows(cur)
    return rows[0] if rows else None


# ----------------------------------------------------------------------------------------------- retained sources
def retain_source(scan_id: str, file_name: str, data: bytes, created_by: str) -> str:
    """Keep an uploaded file (encrypted, expiring) so a recurring scan can re-run it. The caller has already refused files in which
    a hard-coded secret was found. One retained copy per scan."""
    if len(data) > MAX_SOURCE_BYTES:
        raise ExtError(f"only files up to {MAX_SOURCE_BYTES // (1024 * 1024)} MB can be kept for recurring scans")
    org = tenancy.current_org()
    sid = "CSRC-" + uuid.uuid4().hex[:16]
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM cloud_sources WHERE org_id=%s AND expires_at < now()", [org])
        cur.execute("SELECT count(*) FROM cloud_sources WHERE org_id=%s", [org])
        if cur.fetchone()[0] >= MAX_SOURCES_PER_ORG:
            raise ExtError(f"at most {MAX_SOURCES_PER_ORG} files can be kept; delete one first")
        cur.execute("INSERT INTO cloud_sources (source_id, org_id, scan_id, file_name, sha256, size_bytes, content_enc, created_by, expires_at)"
                    " SELECT %s,%s,scan_id,%s,%s,%s,%s,%s, now() + make_interval(days => %s) FROM cloud_scans WHERE scan_id=%s AND org_id=%s",
                    [sid, org, file_name[:200], hashlib.sha256(data).hexdigest(), len(data),
                     crypto.encrypt(base64.b64encode(data).decode("ascii")), created_by[:200], SOURCE_RETENTION_DAYS, scan_id, org])
        if cur.rowcount == 0:
            raise ExtError("scan not found")
    return sid


def source_for_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT source_id, scan_id, file_name, sha256, size_bytes, created_at, expires_at FROM cloud_sources"
                    " WHERE scan_id=%s AND org_id=%s AND expires_at >= now()", [scan_id, tenancy.current_org()])
        return _one(cur)


def load_source(source_id: str) -> Optional[Dict[str, Any]]:
    """Decrypted bytes of a retained, unexpired source of the current organisation."""
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT source_id, file_name, content_enc FROM cloud_sources WHERE source_id=%s AND org_id=%s AND expires_at >= now()",
                    [source_id, tenancy.current_org()])
        row = _one(cur)
    if not row:
        return None
    return {"source_id": row["source_id"], "file_name": row["file_name"], "data": base64.b64decode(crypto.decrypt(row["content_enc"]) or "")}


def delete_source(scan_id: str) -> bool:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM cloud_sources WHERE scan_id=%s AND org_id=%s", [scan_id, tenancy.current_org()])
        return cur.rowcount > 0


# --------------------------------------------------------------------------------------------------- schedules
_SCHED = ("schedule_id, source_id, (SELECT scan_id FROM cloud_sources s WHERE s.source_id=cloud_schedules.source_id) AS scan_id, name, interval_minutes, enabled, extract(epoch from next_run_at) AS next_run_at,"
          " extract(epoch from last_run_at) AS last_run_at, last_scan_id, last_status, created_by, extract(epoch from created_at) AS created_at")


def _sched_rows(cur) -> List[Dict[str, Any]]:
    out = _rows(cur)
    for r in out:
        for k in ("next_run_at", "last_run_at", "created_at"):
            r[k] = float(r[k]) if r.get(k) is not None else None
    return out


def _check_interval(minutes: int) -> int:
    if not isinstance(minutes, int) or isinstance(minutes, bool) or not MIN_INTERVAL_MINUTES <= minutes <= MAX_INTERVAL_MINUTES:
        raise ExtError(f"interval must be between {MIN_INTERVAL_MINUTES} minutes and one year")
    return minutes


def create_schedule(scan_id: str, name: str, interval_minutes: int, created_by: str) -> Dict[str, Any]:
    _check_interval(interval_minutes)
    src = source_for_scan(scan_id)
    if not src:
        raise ExtError("this scan has no kept file; upload it again with 'keep for recurring scans' selected")
    sid = "CSCH-" + uuid.uuid4().hex[:12]
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM cloud_schedules WHERE org_id=%s", [tenancy.current_org()])
        if cur.fetchone()[0] >= MAX_SCHEDULES_PER_ORG:
            raise ExtError(f"at most {MAX_SCHEDULES_PER_ORG} recurring scans are allowed")
        cur.execute("INSERT INTO cloud_schedules (schedule_id, org_id, source_id, name, interval_minutes, next_run_at, created_by)"
                    " VALUES (%s,%s,%s,%s,%s, now() + make_interval(mins => %s), %s)",
                    [sid, tenancy.current_org(), src["source_id"], (name or "").strip()[:200] or str(src["file_name"])[:200],
                     interval_minutes, interval_minutes, created_by[:200]])
    return get_schedule(sid)  # type: ignore[return-value]


def get_schedule(schedule_id: str) -> Optional[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT {_SCHED} FROM cloud_schedules WHERE schedule_id=%s AND org_id=%s", [schedule_id, tenancy.current_org()])
        rows = _sched_rows(cur)
        return rows[0] if rows else None


def list_schedules() -> List[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT {_SCHED} FROM cloud_schedules WHERE org_id=%s ORDER BY created_at DESC LIMIT 200", [tenancy.current_org()])
        return _sched_rows(cur)


def update_schedule(schedule_id: str, *, enabled: Optional[bool] = None, interval_minutes: Optional[int] = None) -> Optional[Dict[str, Any]]:
    if not get_schedule(schedule_id):
        return None
    sets, vals, nxt, nxt_vals = [], [], "next_run_at", []      # next_run_at is assigned once: SQL forbids setting a column twice
    if interval_minutes is not None:
        sets.append("interval_minutes=%s")
        vals.append(_check_interval(interval_minutes))
        nxt, nxt_vals = "LEAST(next_run_at, now() + make_interval(mins => %s))", [interval_minutes]
    if enabled is not None:
        sets.append("enabled=%s")
        vals.append(bool(enabled))
        if enabled:                       # re-enabling must not fire a backlog of missed runs
            nxt = f"GREATEST({nxt}, now())"
    if nxt != "next_run_at":
        sets.append(f"next_run_at={nxt}")
        vals += nxt_vals
    if sets:
        with dbmod.get_conn() as conn:
            conn.cursor().execute(f"UPDATE cloud_schedules SET {', '.join(sets)} WHERE schedule_id=%s AND org_id=%s",
                                  vals + [schedule_id, tenancy.current_org()])
    return get_schedule(schedule_id)


def delete_schedule(schedule_id: str) -> bool:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM cloud_schedules WHERE schedule_id=%s AND org_id=%s", [schedule_id, tenancy.current_org()])
        return cur.rowcount > 0


def record_run(schedule_id: str, scan_id: Optional[str], status: str) -> None:
    with dbmod.get_conn() as conn:
        conn.cursor().execute("UPDATE cloud_schedules SET last_scan_id=%s, last_status=%s WHERE schedule_id=%s AND org_id=%s",
                              [scan_id, status[:100], schedule_id, tenancy.current_org()])


@tenancy.system
def claim_due(limit: int = 20) -> List[Dict[str, Any]]:
    """Cross-tenant and safe in every runner: due rows are claimed with SKIP LOCKED and next_run_at is advanced BEFORE the scan runs,
    so a crash skips a run instead of repeating it. Expired sources disable their schedules instead of running."""
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE cloud_schedules SET enabled=false, last_status='SOURCE_EXPIRED', last_run_at=now()"
                    " WHERE enabled AND next_run_at <= now() AND source_id IN (SELECT source_id FROM cloud_sources WHERE expires_at < now())")
        cur.execute("UPDATE cloud_schedules SET last_run_at=now(), next_run_at = now() + make_interval(mins => interval_minutes)"
                    " WHERE schedule_id IN (SELECT schedule_id FROM cloud_schedules WHERE enabled AND next_run_at <= now()"
                    "                       ORDER BY next_run_at FOR UPDATE SKIP LOCKED LIMIT %s)"
                    " RETURNING schedule_id, org_id, source_id, created_by", [limit])
        return _rows(cur)


@tenancy.system
def purge_expired_sources() -> int:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM cloud_sources WHERE expires_at < now()")
        return cur.rowcount


# --------------------------------------------------------------------------------------------- webhook links
def link_webhook(webhook_id: str, events: List[str], created_by: str) -> Dict[str, Any]:
    ev = sorted({e.strip() for e in events if isinstance(e, str) and e.strip()})
    if not ev or any(e not in CLOUD_EVENTS for e in ev):
        raise ExtError(f"events must be a non-empty subset of {list(CLOUD_EVENTS)}")
    from psycopg.types.json import Jsonb
    org = tenancy.current_org()
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT format FROM webhooks WHERE webhook_id=%s AND org_id=%s", [webhook_id, org])
        row = cur.fetchone()
        if not row:
            raise ExtError("webhook not found")
        if row[0] not in LINKABLE_FORMATS:
            raise ExtError(f"cloud events can only be sent to webhooks in the {list(LINKABLE_FORMATS)} format")
        cur.execute("INSERT INTO cloud_webhook_links (link_id, org_id, webhook_id, events, created_by) VALUES (%s,%s,%s,%s,%s)"
                    " ON CONFLICT (org_id, webhook_id) DO UPDATE SET events=EXCLUDED.events",
                    ["CWL-" + uuid.uuid4().hex[:12], org, webhook_id, Jsonb(ev), created_by[:200]])
    return {"webhook_id": webhook_id, "events": ev}


def list_webhook_links() -> List[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT l.webhook_id, w.name, w.format, w.enabled, l.events FROM cloud_webhook_links l"
                    " JOIN webhooks w ON w.webhook_id=l.webhook_id AND w.org_id=l.org_id WHERE l.org_id=%s ORDER BY l.created_at DESC",
                    [tenancy.current_org()])
        return _rows(cur)


def unlink_webhook(webhook_id: str) -> bool:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM cloud_webhook_links WHERE webhook_id=%s AND org_id=%s", [webhook_id, tenancy.current_org()])
        return cur.rowcount > 0


def emit(event: str, data: Dict[str, Any]) -> int:
    """Queue a delivery on every enabled, linked webhook of the current org. Best effort: never raises into the caller. Uses the
    existing ``webhook`` job kind, so signing, SSRF pinning, retries and the delivery log are exactly the existing ones."""
    if event not in CLOUD_EVENTS:
        return 0
    n = 0
    try:
        from psycopg.types.json import Jsonb
        with dbmod.get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT l.webhook_id FROM cloud_webhook_links l JOIN webhooks w ON w.webhook_id=l.webhook_id AND w.org_id=l.org_id"
                        " WHERE l.org_id=%s AND w.enabled AND l.events @> %s", [tenancy.current_org(), Jsonb([event])])
            ids = [r[0] for r in cur.fetchall()]
        for wid in ids:
            jobs.enqueue("webhook", {"webhook_id": wid, "event": event, "data": data}, created_by="cloud", max_attempts=5)
            n += 1
    except Exception:  # noqa: BLE001 - notifications are best effort and must not break scanning
        import logging
        logging.getLogger("sih26155").exception("cloud emit(%s) failed", event)
    return n


# ------------------------------------------------------------------------------------------------ asset links
def link_asset(scan_id: str, asset_id: str, created_by: str) -> Dict[str, Any]:
    org = tenancy.current_org()
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT name FROM assets WHERE asset_id=%s AND org_id=%s", [asset_id, org])
        asset = cur.fetchone()
        if not asset:
            raise ExtError("asset not found")
        cur.execute("SELECT 1 FROM cloud_scans WHERE scan_id=%s AND org_id=%s", [scan_id, org])
        if not cur.fetchone():
            raise ExtError("scan not found")
        cur.execute("INSERT INTO cloud_asset_links (link_id, org_id, scan_id, asset_id, created_by) VALUES (%s,%s,%s,%s,%s)"
                    " ON CONFLICT (org_id, scan_id, asset_id) DO NOTHING",
                    ["CAL-" + uuid.uuid4().hex[:12], org, scan_id, asset_id, created_by[:200]])
    return {"scan_id": scan_id, "asset_id": asset_id, "asset_name": asset[0]}


def links_for_scan(scan_id: str) -> List[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT l.asset_id, a.name AS asset_name FROM cloud_asset_links l JOIN assets a ON a.asset_id=l.asset_id AND a.org_id=l.org_id"
                    " WHERE l.scan_id=%s AND l.org_id=%s ORDER BY l.created_at", [scan_id, tenancy.current_org()])
        return _rows(cur)


def links_for_asset(asset_id: str) -> List[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT s.scan_id, s.file_name, s.status, s.summary, s.created_at FROM cloud_asset_links l"
                    " JOIN cloud_scans s ON s.scan_id=l.scan_id AND s.org_id=l.org_id WHERE l.asset_id=%s AND l.org_id=%s"
                    " ORDER BY s.created_at DESC LIMIT 50", [asset_id, tenancy.current_org()])
        return _rows(cur)


def unlink_asset(scan_id: str, asset_id: str) -> bool:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM cloud_asset_links WHERE scan_id=%s AND asset_id=%s AND org_id=%s", [scan_id, asset_id, tenancy.current_org()])
        return cur.rowcount > 0
