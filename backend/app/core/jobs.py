"""Postgres-backed job queue (no extra infrastructure).

Lifecycle:  QUEUED -> RUNNING -> COMPLETED
                         |  \\-> QUEUED (retry with exponential backoff)   when attempts < max_attempts
                         \\---> FAILED                                      when out of attempts / permanent error
            QUEUED -> CANCELLED (user)      RUNNING + cancel_requested -> CANCELLED (when the worker checks)

Workers claim with ``FOR UPDATE SKIP LOCKED`` so any number of worker processes/containers can run
concurrently without double-processing. A worker that dies leaves a RUNNING row with an old ``locked_at``;
``requeue_stale`` returns such jobs to the queue. Jobs are tenant-scoped: API-side functions only see the
caller's org; worker-side functions (claim/complete/fail) are cross-tenant by design and re-enter the job's
org before touching business data.
"""
from __future__ import annotations
import uuid
from typing import Any, Dict, List, Optional

from app.core import config as cfg
from app.core import db as dbmod
from app.core import tenancy

QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED = "QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"
TERMINAL = (COMPLETED, FAILED, CANCELLED)
KINDS = ("audit", "report", "webhook", "collect")

_COLS = ("job_id, kind, status, org_id, payload, result, error, progress, attempts, max_attempts, priority, "
         "batch_id, created_by, cancel_requested, locked_by, "
         "extract(epoch from created_at) AS created_at, extract(epoch from started_at) AS started_at, "
         "extract(epoch from finished_at) AS finished_at, extract(epoch from run_after) AS run_after")


class QueueFull(Exception):
    pass


def _row(cur, r) -> Dict[str, Any]:
    cols = [d[0] for d in cur.description]
    d = dict(zip(cols, r))
    for k in ("created_at", "started_at", "finished_at", "run_after"):
        if d.get(k) is not None:
            d[k] = float(d[k])
    d["payload"] = d.get("payload") or {}
    d["result"] = d.get("result") or {}
    return d


def public(job: Dict[str, Any]) -> Dict[str, Any]:
    """API view of a job (no internal lock fields)."""
    keep = ("job_id", "kind", "status", "progress", "error", "attempts", "max_attempts", "batch_id", "created_by",
            "payload", "result", "created_at", "started_at", "finished_at", "cancel_requested")
    return {k: job.get(k) for k in keep}


# ------------------------------------------------------------------ API side (tenant scoped)
def enqueue(kind: str, payload: Dict[str, Any], *, batch_id: Optional[str] = None, max_attempts: Optional[int] = None,
            priority: int = 0, created_by: Optional[str] = None) -> str:
    if kind not in KINDS:
        raise ValueError(f"unknown job kind {kind!r}")
    from psycopg.types.json import Jsonb
    org = tenancy.current_org()
    job_id = "JOB-" + uuid.uuid4().hex[:12].upper()
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("SELECT count(*) FROM jobs WHERE org_id=%s AND status IN ('QUEUED','RUNNING')", (org,))
        (pending,) = cur.fetchone()
        if pending >= cfg.MAX_QUEUED_JOBS_PER_ORG:
            raise QueueFull(f"too many pending jobs ({pending}); wait for the queue to drain")
        cur.execute(
            "INSERT INTO jobs (job_id, kind, status, org_id, payload, max_attempts, priority, batch_id, created_by, data) "
            "VALUES (%s,%s,'QUEUED',%s,%s,%s,%s,%s,%s,'{}'::jsonb)",
            (job_id, kind, org, Jsonb(payload), max_attempts or cfg.JOB_MAX_ATTEMPTS, priority, batch_id, created_by))
    return job_id


def get(job_id: str) -> Optional[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(f"SELECT {_COLS} FROM jobs WHERE job_id=%s AND org_id=%s", (job_id, tenancy.current_org()))
        r = cur.fetchone()
        return _row(cur, r) if r else None


def list_jobs(*, status: Optional[str] = None, kind: Optional[str] = None, batch_id: Optional[str] = None,
              limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    clauses, vals = ["org_id=%s"], [tenancy.current_org()]
    for col, v in (("status", status), ("kind", kind), ("batch_id", batch_id)):
        if v:
            clauses.append(f"{col}=%s")
            vals.append(v.upper() if col == "status" else v)
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(f"SELECT {_COLS} FROM jobs WHERE {' AND '.join(clauses)} ORDER BY created_at DESC LIMIT %s OFFSET %s",
                    vals + [limit, offset])
        return [_row(cur, r) for r in cur.fetchall()]


def batch_summary(batch_id: str) -> Optional[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("SELECT status, count(*), coalesce(avg(progress),0) FROM jobs WHERE batch_id=%s AND org_id=%s GROUP BY status",
                    (batch_id, tenancy.current_org()))
        rows = cur.fetchall()
    if not rows:
        return None
    counts = {s: int(n) for s, n, _ in rows}
    total = sum(counts.values())
    done = sum(counts.get(s, 0) for s in TERMINAL)
    return {"batch_id": batch_id, "total": total, "counts": counts, "finished": done,
            "progress_pct": round(100.0 * done / total, 1) if total else 0.0,
            "state": "COMPLETED" if done == total and not counts.get(FAILED) and not counts.get(CANCELLED)
            else ("FINISHED_WITH_ERRORS" if done == total else "RUNNING")}


def cancel(job_id: str) -> Optional[str]:
    """QUEUED -> CANCELLED immediately; RUNNING -> cancel requested. Returns the new status or None."""
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("UPDATE jobs SET status='CANCELLED', finished_at=now() WHERE job_id=%s AND org_id=%s AND status='QUEUED' "
                    "RETURNING status", (job_id, tenancy.current_org()))
        if cur.fetchone():
            return CANCELLED
        cur.execute("UPDATE jobs SET cancel_requested=true WHERE job_id=%s AND org_id=%s AND status='RUNNING' "
                    "RETURNING status", (job_id, tenancy.current_org()))
        return RUNNING if cur.fetchone() else None


def retry(job_id: str) -> bool:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("UPDATE jobs SET status='QUEUED', attempts=0, error=NULL, progress=0, cancel_requested=false, "
                    "run_after=now(), finished_at=NULL, locked_by=NULL, locked_at=NULL "
                    "WHERE job_id=%s AND org_id=%s AND status IN ('FAILED','CANCELLED') RETURNING job_id",
                    (job_id, tenancy.current_org()))
        return cur.fetchone() is not None


# ------------------------------------------------------------- worker side (cross-tenant)
@tenancy.system
def claim(worker_id: str) -> Optional[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(
            "UPDATE jobs SET status='RUNNING', locked_by=%s, locked_at=now(), started_at=COALESCE(started_at, now()), "
            "attempts=attempts+1, progress=GREATEST(progress,5) "
            "WHERE job_id = (SELECT job_id FROM jobs WHERE status='QUEUED' AND run_after <= now() "
            "                ORDER BY priority DESC, created_at FOR UPDATE SKIP LOCKED LIMIT 1) "
            f"RETURNING {_COLS}", (worker_id,))
        r = cur.fetchone()
        return _row(cur, r) if r else None


@tenancy.system
def heartbeat(job_id: str, worker_id: str, progress: Optional[int] = None) -> bool:
    """Keep the lock fresh; returns False when the job was cancelled / lost (the worker should stop)."""
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("UPDATE jobs SET locked_at=now(), progress=COALESCE(%s, progress) "
                    "WHERE job_id=%s AND locked_by=%s AND status='RUNNING' RETURNING cancel_requested",
                    (progress, job_id, worker_id))
        r = cur.fetchone()
        return bool(r) and not r[0]


@tenancy.system
def complete(job_id: str, worker_id: str, result: Dict[str, Any]) -> None:
    from psycopg.types.json import Jsonb
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("UPDATE jobs SET status='COMPLETED', result=%s, progress=100, finished_at=now(), error=NULL, "
                    "locked_by=NULL, locked_at=NULL WHERE job_id=%s AND locked_by=%s AND status='RUNNING'",
                    (Jsonb(result), job_id, worker_id))


@tenancy.system
def mark_cancelled(job_id: str, worker_id: str) -> None:
    with dbmod.get_conn() as conn:
        conn.cursor().execute(  # type: ignore[attr-defined]
            "UPDATE jobs SET status='CANCELLED', finished_at=now(), locked_by=NULL, locked_at=NULL "
            "WHERE job_id=%s AND locked_by=%s", (job_id, worker_id))


@tenancy.system
def fail(job_id: str, worker_id: str, error: str, *, permanent: bool = False) -> str:
    """Retry with exponential backoff (5s, 10s, 20s ...) until max_attempts, else FAILED. Returns new status."""
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(
            "UPDATE jobs SET error=%s, locked_by=NULL, locked_at=NULL, "
            "status = CASE WHEN %s OR attempts >= max_attempts THEN 'FAILED' ELSE 'QUEUED' END, "
            "finished_at = CASE WHEN %s OR attempts >= max_attempts THEN now() ELSE NULL END, "
            "run_after = CASE WHEN %s OR attempts >= max_attempts THEN run_after "
            "                 ELSE now() + make_interval(secs => 5 * power(2, attempts - 1)) END "
            "WHERE job_id=%s AND locked_by=%s RETURNING status",
            (error[:2000], permanent, permanent, permanent, job_id, worker_id))
        r = cur.fetchone()
        return r[0] if r else FAILED


@tenancy.system
def requeue_stale(timeout_s: Optional[int] = None) -> int:
    """Recover jobs whose worker died (no heartbeat for timeout_s). Out-of-attempts jobs become FAILED."""
    timeout_s = timeout_s or cfg.JOB_STALE_SECONDS
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(
            "UPDATE jobs SET locked_by=NULL, locked_at=NULL, error='worker stopped responding', "
            "status = CASE WHEN attempts >= max_attempts THEN 'FAILED' ELSE 'QUEUED' END, "
            "finished_at = CASE WHEN attempts >= max_attempts THEN now() ELSE NULL END, run_after = now() "
            "WHERE status='RUNNING' AND locked_at < now() - make_interval(secs => %s)", (timeout_s,))
        return cur.rowcount


@tenancy.system
def purge(older_than_days: Optional[int] = None) -> int:
    days = older_than_days or cfg.JOB_RETENTION_DAYS
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("DELETE FROM jobs WHERE status IN ('COMPLETED','FAILED','CANCELLED') AND kind IN ('audit','report','webhook') "
                    "AND finished_at < now() - make_interval(days => %s)", (days,))
        return cur.rowcount
