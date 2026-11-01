"""Recurring re-audits of an asset's latest configuration.

Why this is useful without live device collection: findings change even when the config does not - a new CVE is
published, a control pack is updated. A schedule re-audits the latest uploaded config on an interval and the
history layer reports exactly what changed (and whether the cause was the config or the knowledge base).

The scheduler tick is cross-tenant and safe to run in every worker: due rows are claimed with
``FOR UPDATE SKIP LOCKED`` and ``next_run_at`` is advanced BEFORE the job is enqueued, so a crash skips a run
instead of duplicating it.
"""
from __future__ import annotations
import logging
import uuid
from typing import Any, Dict, List, Optional

from psycopg.types.json import Jsonb

from app.core import config as cfg
from app.core import db as dbmod
from app.core import jobs, tenancy

log = logging.getLogger("sih26155")
_COLS = ("schedule_id, name, asset_id, interval_minutes, frameworks, run_cve, enabled, last_job_id, last_status, created_by, "
         "extract(epoch from next_run_at) AS next_run_at, extract(epoch from last_run_at) AS last_run_at, "
         "extract(epoch from created_at) AS created_at")
FRAMEWORKS = {"CIS", "NIST", "STIG", "ISO27001", "CERTIN"}


class ScheduleError(ValueError):
    pass


def _rows(cur) -> List[Dict[str, Any]]:
    cols = [d[0] for d in cur.description]
    out = []
    for r in cur.fetchall():
        d = dict(zip(cols, r))
        for k in ("next_run_at", "last_run_at", "created_at"):
            d[k] = float(d[k]) if d.get(k) is not None else None
        out.append(d)
    return out


def _validate(interval_minutes: int, frameworks: List[str]) -> List[str]:
    if interval_minutes < cfg.SCHEDULE_MIN_MINUTES:
        raise ScheduleError(f"interval must be at least {cfg.SCHEDULE_MIN_MINUTES} minutes")
    if interval_minutes > 60 * 24 * 366:
        raise ScheduleError("interval must be at most one year")
    fw = [f.strip().upper() for f in frameworks if f.strip()]
    if not fw or any(f not in FRAMEWORKS for f in fw):
        raise ScheduleError(f"frameworks must be a non-empty subset of {sorted(FRAMEWORKS)}")
    return fw


def create(name: str, asset_id: str, interval_minutes: int, frameworks: List[str], run_cve: bool,
           created_by: Optional[str], start_in_minutes: int = 0) -> Dict[str, Any]:
    fw = _validate(interval_minutes, frameworks)
    sid = "SCH-" + uuid.uuid4().hex[:10].upper()
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("SELECT count(*) FROM schedules WHERE org_id=%s", (tenancy.current_org(),))
        if cur.fetchone()[0] >= cfg.MAX_SCHEDULES_PER_ORG:
            raise ScheduleError(f"schedule limit reached ({cfg.MAX_SCHEDULES_PER_ORG})")
        cur.execute("INSERT INTO schedules (schedule_id, org_id, name, asset_id, interval_minutes, frameworks, run_cve, "
                    "created_by, next_run_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s, now() + make_interval(mins => %s))",
                    (sid, tenancy.current_org(), name.strip()[:200], asset_id, interval_minutes, Jsonb(fw), run_cve,
                     created_by, max(0, start_in_minutes)))
    return get(sid)  # type: ignore[return-value]


def get(schedule_id: str) -> Optional[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(f"SELECT {_COLS} FROM schedules WHERE schedule_id=%s AND org_id=%s", (schedule_id, tenancy.current_org()))
        rows = _rows(cur)
        return rows[0] if rows else None


def list_schedules(asset_id: Optional[str] = None) -> List[Dict[str, Any]]:
    clauses, vals = ["org_id=%s"], [tenancy.current_org()]
    if asset_id:
        clauses.append("asset_id=%s")
        vals.append(asset_id)
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(f"SELECT {_COLS} FROM schedules WHERE {' AND '.join(clauses)} ORDER BY created_at DESC LIMIT 500", vals)
        return _rows(cur)


def update(schedule_id: str, *, enabled: Optional[bool] = None, interval_minutes: Optional[int] = None,
           name: Optional[str] = None, frameworks: Optional[List[str]] = None, run_cve: Optional[bool] = None) -> Optional[Dict[str, Any]]:
    cur_row = get(schedule_id)
    if not cur_row:
        return None
    sets, vals = [], []
    if interval_minutes is not None:
        _validate(interval_minutes, cur_row["frameworks"])
        sets += ["interval_minutes=%s", "next_run_at=LEAST(next_run_at, now() + make_interval(mins => %s))"]
        vals += [interval_minutes, interval_minutes]
    if frameworks is not None:
        sets.append("frameworks=%s")
        vals.append(Jsonb(_validate(cur_row["interval_minutes"], frameworks)))
    if enabled is not None:
        sets.append("enabled=%s")
        vals.append(enabled)
        if enabled:    # re-enabling must not fire a backlog of missed runs
            sets.append("next_run_at=GREATEST(next_run_at, now())")
    if name is not None:
        sets.append("name=%s")
        vals.append(name.strip()[:200])
    if run_cve is not None:
        sets.append("run_cve=%s")
        vals.append(run_cve)
    if sets:
        with dbmod.get_conn() as conn:
            conn.cursor().execute(  # type: ignore[attr-defined]
                f"UPDATE schedules SET {', '.join(sets)} WHERE schedule_id=%s AND org_id=%s",
                vals + [schedule_id, tenancy.current_org()])
    return get(schedule_id)


def delete(schedule_id: str) -> bool:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("DELETE FROM schedules WHERE schedule_id=%s AND org_id=%s", (schedule_id, tenancy.current_org()))
        return cur.rowcount > 0


def latest_configuration_id(asset_id: str) -> Optional[str]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("SELECT configuration_id FROM configurations WHERE org_id=%s AND asset_id=%s "
                    "ORDER BY created_at DESC LIMIT 1", (tenancy.current_org(), asset_id))
        r = cur.fetchone()
        return r[0] if r else None


def _fire(sched: Dict[str, Any]) -> str:
    """Enqueue one audit for a schedule (caller has bound the schedule's org). Returns the status string."""
    cid = latest_configuration_id(sched["asset_id"])
    if not cid:
        return "NO_CONFIG"
    try:
        jid = jobs.enqueue("audit", {"asset_id": sched["asset_id"], "configuration_id": cid,
                                     "frameworks": sched["frameworks"], "run_cve": sched["run_cve"],
                                     "schedule_id": sched["schedule_id"]},
                           created_by=sched.get("created_by") or "scheduler")
    except jobs.QueueFull:
        return "QUEUE_FULL"
    with dbmod.get_conn() as conn:
        conn.cursor().execute("UPDATE schedules SET last_job_id=%s, last_status='QUEUED' WHERE schedule_id=%s",  # type: ignore[attr-defined]
                              (jid, sched["schedule_id"]))
    return "QUEUED"


def run_now(schedule_id: str) -> Optional[str]:
    s = get(schedule_id)
    if not s:
        return None
    st = _fire(s)
    with dbmod.get_conn() as conn:
        conn.cursor().execute("UPDATE schedules SET last_run_at=now(), last_status=%s WHERE schedule_id=%s",  # type: ignore[attr-defined]
                              (st, schedule_id))
    return st


@tenancy.system
def _claim_due(limit: int):
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(
            "UPDATE schedules SET last_run_at=now(), next_run_at = now() + make_interval(mins => interval_minutes) "
            "WHERE schedule_id IN (SELECT schedule_id FROM schedules WHERE enabled AND next_run_at <= now() "
            "                      ORDER BY next_run_at FOR UPDATE SKIP LOCKED LIMIT %s) "
            "RETURNING schedule_id, org_id, asset_id, frameworks, run_cve, created_by", (limit,))
        return cur.fetchall()


@tenancy.system
def _set_status(schedule_id: str, status: str) -> None:
    with dbmod.get_conn() as conn:
        conn.cursor().execute("UPDATE schedules SET last_status=%s WHERE schedule_id=%s", (status[:100], schedule_id))  # type: ignore[attr-defined]


def run_due(limit: int = 50) -> int:
    """Scheduler tick (cross-tenant, safe in every worker). Returns how many schedules fired."""
    due = _claim_due(limit)
    fired = 0
    for sid, org, asset, fw, run_cve, by in due:
        try:
            with tenancy.use_org(org):
                st = _fire({"schedule_id": sid, "asset_id": asset, "frameworks": fw, "run_cve": run_cve, "created_by": by})
        except Exception as e:              # noqa: BLE001 - one bad schedule must not block the others
            log.exception("schedule %s failed to fire", sid)
            st = f"ERROR: {type(e).__name__}"
        _set_status(sid, st)
        fired += st == "QUEUED"
    return fired
