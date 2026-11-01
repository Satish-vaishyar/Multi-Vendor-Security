"""Background worker:  python -m app.worker  [--once]

Claims jobs from the Postgres queue and runs them. Run as many processes/containers as you need - claiming uses
FOR UPDATE SKIP LOCKED, so jobs are never processed twice. SIGTERM/SIGINT finish the current job, then exit.
"""
from __future__ import annotations
import logging
import os
import signal
import socket
import threading
import time
import uuid
from typing import Optional

from app.core import auditlog
from app.core import config as cfg
from app.core import jobs, schedules, tenancy
from app.core import metrics
from app.services import events, history, job_handlers

log = logging.getLogger("sih26155.worker")


def new_worker_id() -> str:
    return f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"


def process_one(worker_id: str) -> bool:
    """Claim and run one job. Returns False when the queue had nothing runnable."""
    job = jobs.claim(worker_id)
    if not job:
        return False
    jid, kind = job["job_id"], job["kind"]
    actor = {"id": f"worker:{worker_id}", "email": job.get("created_by"), "role": "WORKER", "org_id": job["org_id"]}
    t0 = time.time()
    handler = job_handlers.HANDLERS.get(kind)
    try:
        if handler is None:
            raise job_handlers.PermanentJobError(f"no handler for job kind {kind!r}")
        if not jobs.heartbeat(jid, worker_id, 10):        # cancelled while still queued-but-claimed
            jobs.mark_cancelled(jid, worker_id)
            return True
        with tenancy.use_org(job["org_id"]):
            result = handler(job)
            _notify(job, result)
        if not jobs.heartbeat(jid, worker_id, 95):
            jobs.mark_cancelled(jid, worker_id)
            auditlog.record("job.cancelled", actor=actor, detail={"job_id": jid, "kind": kind}, org_id=job["org_id"])
            return True
        jobs.complete(jid, worker_id, result)
        auditlog.record("job.completed", actor=actor, org_id=job["org_id"],
                        detail={"job_id": jid, "kind": kind, "seconds": round(time.time() - t0, 2)})
        log.info("job %s (%s) completed in %.1fs", jid, kind, time.time() - t0)
    except job_handlers.PermanentJobError as e:
        status = jobs.fail(jid, worker_id, str(e), permanent=True)
        _notify_failure(job, str(e))
        auditlog.record("job.failed", actor=actor, org_id=job["org_id"], detail={"job_id": jid, "kind": kind, "error": str(e)[:300]})
        log.warning("job %s failed permanently: %s", jid, e)
    except Exception as e:                                # noqa: BLE001 - any other error is retried with backoff
        status = jobs.fail(jid, worker_id, f"{type(e).__name__}: {e}")
        log.exception("job %s attempt %s/%s failed -> %s", jid, job["attempts"], job["max_attempts"], status)
        if status == jobs.FAILED:
            _notify_failure(job, f"{type(e).__name__}: {e}")
            auditlog.record("job.failed", actor=actor, org_id=job["org_id"],
                            detail={"job_id": jid, "kind": kind, "error": f"{type(e).__name__}: {e}"[:300]})
    return True


def _notify(job, result) -> None:
    """Fire webhooks for a finished audit (org context is bound by the caller)."""
    if job["kind"] != "audit":
        return
    from app.core import persist as db
    asset = db.get("assets", str(result.get("asset_id", ""))) or {}
    data = {**result, "asset_name": asset.get("name"), "schedule_id": job["payload"].get("schedule_id"), "job_id": job["job_id"]}
    events.emit("audit.completed", data)
    if (result.get("changes") or {}).get("new_critical_high", 0) > 0:
        events.emit("finding.new_critical_high", data)


def _notify_failure(job, error: str) -> None:
    if job["kind"] not in ("audit", "report"):       # a failing webhook must never trigger more webhooks
        return
    with tenancy.use_org(job["org_id"]):
        events.emit("job.failed", {"job_id": job["job_id"], "kind": job["kind"], "error": error[:300]})


def drain(worker_id: Optional[str] = None, max_jobs: int = 10_000) -> int:
    """Process until the queue has nothing runnable (used by tests and one-shot runs)."""
    wid, n = worker_id or new_worker_id(), 0
    while n < max_jobs and process_one(wid):
        n += 1
    return n


_cve_sync_lock = threading.Lock()
_cve_last_sync = 0.0


def cve_auto_sync(force: bool = False) -> Optional[dict]:
    """Refresh the local CVE KB (NVD delta + CISA KEV) when CVE_AUTO_SYNC_HOURS has elapsed. Runs in a
    background thread so audits are never blocked; failures are logged, never raised. Public data only."""
    global _cve_last_sync
    if not force and (cfg.CVE_AUTO_SYNC_HOURS <= 0 or time.time() - _cve_last_sync < cfg.CVE_AUTO_SYNC_HOURS * 3600):
        return None
    if not _cve_sync_lock.acquire(blocking=False):
        return None
    _cve_last_sync = time.time()                      # set first: a failing sync retries next interval, not every minute

    def _run() -> None:
        try:
            from app.services.integration import cve_layer
            from src.cve.kev import sync_kev
            out = cve_layer()["sync_now"](None, 25, 2000, keywords=None, since_days=cfg.CVE_AUTO_SYNC_DAYS)
            kev = sync_kev()
            log.info("cve auto-sync: nvd=%s kev=%s", {k: out.get(k) for k in ("ok", "added", "updated", "total", "error")}, kev)
        except Exception:                             # noqa: BLE001
            log.exception("cve auto-sync failed")
        finally:
            _cve_sync_lock.release()
    threading.Thread(target=_run, name="cve-auto-sync", daemon=True).start()
    return {"started": True}


def run_forever(stop: threading.Event, poll_s: Optional[float] = None) -> None:
    wid, poll = new_worker_id(), poll_s or cfg.WORKER_POLL_SECONDS
    last_maint = last_purge = 0.0
    log.info("worker %s started (poll %.1fs)", wid, poll)
    while not stop.is_set():
        try:
            if time.time() - last_maint > 60:                # recover dead workers' jobs, drop old data, fire schedules
                recovered = jobs.requeue_stale()
                if recovered:
                    log.warning("re-queued %d stale job(s)", recovered)
                cve_auto_sync()
                fired = schedules.run_due()
                if fired:
                    log.info("scheduler queued %d recurring audit(s)", fired)
                ran_retention = False
                if time.time() - last_purge > 3600:
                    jobs.purge()
                    history.purge()
                    if cfg.RETENTION_ENABLED:
                        from app.services import retention
                        retention.run()
                        ran_retention = True
                    last_purge = time.time()
                last_maint = time.time()
                metrics.worker_heartbeat(wid, maintenance=True, retention=ran_retention)
            if not process_one(wid):
                stop.wait(poll)
        except Exception:                                     # noqa: BLE001 - DB hiccup must not kill the worker
            log.exception("worker loop error; retrying")
            stop.wait(min(30.0, poll * 5))
    log.info("worker %s stopped", wid)


def start_embedded() -> threading.Event:
    """Run a worker thread inside the API process (development / single-container installs)."""
    stop = threading.Event()
    threading.Thread(target=run_forever, args=(stop,), name="embedded-worker", daemon=True).start()
    return stop


def main(argv: Optional[list] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="SIH-26155 background worker")
    ap.add_argument("--once", action="store_true", help="drain the queue and exit")
    args = ap.parse_args(argv)
    from app.core import logsetup
    logsetup.configure()
    problems = cfg.validate_production()
    if problems:
        raise SystemExit("Unsafe production configuration:\n - " + "\n - ".join(problems))
    from app.services import integration
    integration._ensure_bridge()
    if args.once:
        print(f"processed {drain()} job(s)")
        return 0
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    run_forever(stop)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
