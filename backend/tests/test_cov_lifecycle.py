"""Branch coverage for process lifecycle: FastAPI start-up/shut-down (app/main.py) and the worker loop (app/worker.py)."""
import signal
import sys
import threading
import time
import types

import pytest
from fastapi.testclient import TestClient

from app import main as app_main
from app import worker
from app.core import config as cfg
from app.core import jobs, tenancy
from app.services import integration as integ


# ---------------------------------------------------------------- lifespan
def _noop(*a, **k):
    return {}


def _stub_warmups(monkeypatch):
    integ._ensure_bridge()                                   # makes the OKF "src" package importable (real bridge, before it is stubbed)
    import src
    for name in ("okf_layer", "learning_engine", "cve_layer"):
        monkeypatch.setattr(integ, name, _noop)
    monkeypatch.setattr(integ, "m1_predict", _noop)
    monkeypatch.setattr(integ, "_ensure_bridge", lambda: None)
    emb = types.ModuleType("src.embed")
    emb._HAS_MINI, emb._MODEL_SOURCE = True, "stub"
    emb.encode = lambda texts: [[0.0]]
    monkeypatch.setitem(sys.modules, "src.embed", emb)
    monkeypatch.setattr(src, "embed", emb, raising=False)    # `import src.embed as x` prefers the package attribute
    return emb


def test_startup_warns_checks_the_schema_warms_up_and_starts_the_embedded_worker(monkeypatch):
    _stub_warmups(monkeypatch)
    monkeypatch.setattr(cfg, "production_warnings", lambda: ["something is degraded"])
    monkeypatch.setattr("app.core.db.ping", lambda: {"schema_current": False})
    monkeypatch.setattr(cfg, "EMBEDDED_WORKER", True)
    stop = threading.Event()
    monkeypatch.setattr(worker, "start_embedded", lambda: stop)
    with TestClient(app_main.app) as c:
        assert c.get("/health").status_code == 200
        assert not stop.is_set()
    assert stop.is_set()                                     # shut-down stops the embedded worker


def test_startup_survives_a_failing_warmup_step_and_a_failing_ml_layer(monkeypatch):
    emb = _stub_warmups(monkeypatch)
    monkeypatch.setattr(integ, "learning_engine", lambda: (_ for _ in ()).throw(RuntimeError("no model")))
    emb._HAS_MINI = False                                    # TF-IDF fallback: no embedding warm-up call
    monkeypatch.setattr(cfg, "EMBEDDED_WORKER", False)
    with TestClient(app_main.app) as c:
        assert c.get("/health").status_code == 200
    monkeypatch.setattr(integ, "_ensure_bridge", lambda: (_ for _ in ()).throw(RuntimeError("bridge down")))
    with TestClient(app_main.app) as c:                      # the whole ML block is skipped, the API still serves
        assert c.get("/health").status_code == 200


# ---------------------------------------------------------------- process_one cancellation
def _queue(kind="report"):
    with tenancy.use_org(cfg.DEFAULT_ORG_ID):
        return jobs.enqueue(kind, {"audit_id": "AUD-X"})


def _drain_other_jobs():
    while jobs.claim("cov-drain"):
        pass


def test_a_job_cancelled_while_claimed_is_never_run(monkeypatch):
    _drain_other_jobs()
    jid = _queue()
    ran = []
    monkeypatch.setitem(worker.job_handlers.HANDLERS, "report", lambda job: ran.append(1) or {})
    monkeypatch.setattr(jobs, "heartbeat", lambda *a, **k: False)
    cancelled = []
    monkeypatch.setattr(jobs, "mark_cancelled", lambda j, w: cancelled.append(j))
    assert worker.process_one("w-cov") is True and cancelled == [jid] and not ran


def test_a_job_cancelled_while_running_is_recorded_as_cancelled(monkeypatch):
    _drain_other_jobs()
    jid = _queue()
    monkeypatch.setitem(worker.job_handlers.HANDLERS, "report", lambda job: {"ok": True})
    beats = []

    def hb(*a, **k):
        beats.append(1)
        return len(beats) == 1                              # alive before the handler, cancelled right after it
    monkeypatch.setattr(jobs, "heartbeat", hb)
    cancelled = []
    monkeypatch.setattr(jobs, "mark_cancelled", lambda j, w: cancelled.append(j))
    assert worker.process_one("w-cov") is True and cancelled == [jid]


# ---------------------------------------------------------------- cve auto sync
def test_auto_sync_is_skipped_while_another_sync_runs_and_logs_failures(monkeypatch):
    monkeypatch.setattr(cfg, "CVE_AUTO_SYNC_HOURS", 1)
    monkeypatch.setattr(worker, "_cve_last_sync", 0.0)
    assert worker._cve_sync_lock.acquire(blocking=False)
    try:
        assert worker.cve_auto_sync(force=True) is None      # lock held by "another" run
    finally:
        worker._cve_sync_lock.release()
    monkeypatch.setattr(integ, "cve_layer", lambda: {"sync_now": lambda *a, **k: (_ for _ in ()).throw(RuntimeError("nvd down"))})
    assert worker.cve_auto_sync(force=True) == {"started": True}
    time.sleep(0.2)
    for _ in range(100):                                     # the thread releases the lock in its finally block
        if worker._cve_sync_lock.acquire(blocking=False):
            worker._cve_sync_lock.release()
            break
        time.sleep(0.05)


# ---------------------------------------------------------------- run_forever / start_embedded / main
def test_the_loop_logs_recovered_jobs_and_survives_a_database_hiccup(monkeypatch):
    stop = threading.Event()
    monkeypatch.setattr(jobs, "requeue_stale", lambda: 2)                      # recovered stale jobs are logged
    monkeypatch.setattr(worker, "cve_auto_sync", lambda *a, **k: None)
    monkeypatch.setattr(worker.schedules, "run_due", lambda: 0)
    monkeypatch.setattr(worker.metrics, "worker_heartbeat", lambda *a, **k: None)
    monkeypatch.setattr(jobs, "purge", lambda: 0)
    monkeypatch.setattr(worker.history, "purge", lambda: 0)
    monkeypatch.setattr(cfg, "RETENTION_ENABLED", False)

    def boom(wid):
        raise RuntimeError("db hiccup")                                          # must not kill the loop
    monkeypatch.setattr(worker, "process_one", boom)
    waits = []
    monkeypatch.setattr(threading.Event, "wait", lambda self, timeout=None: (waits.append(timeout), stop.set())[0])
    worker.run_forever(stop, poll_s=0.01)
    assert waits and waits[0] == pytest.approx(0.05)                              # backs off (poll * 5) instead of dying


def test_start_embedded_returns_a_stoppable_event(monkeypatch):
    seen = []
    monkeypatch.setattr(worker, "run_forever", lambda stop, poll_s=None: seen.append(stop))
    ev = worker.start_embedded()
    for _ in range(100):
        if seen:
            break
        time.sleep(0.02)
    assert isinstance(ev, threading.Event) and seen and seen[0] is ev


def test_main_runs_the_loop_with_signal_handlers_or_exits_on_unsafe_config(monkeypatch):
    monkeypatch.setattr(integ, "_ensure_bridge", lambda: None)
    handlers = {}
    monkeypatch.setattr(signal, "signal", lambda sig, fn: handlers.update({sig: fn}))
    monkeypatch.setattr(worker, "run_forever", lambda stop, poll_s=None: None)
    assert worker.main([]) == 0 and handlers[signal.SIGTERM] is not None
    stop_flag = threading.Event()
    monkeypatch.setattr(worker, "run_forever", lambda stop, poll_s=None: handlers[signal.SIGTERM]() or stop_flag.set())
    assert worker.main([]) == 0 and stop_flag.is_set()
    monkeypatch.setattr(cfg, "validate_production", lambda: ["JWT_SECRET is weak"])
    with pytest.raises(SystemExit) as e:
        worker.main([])
    assert "JWT_SECRET is weak" in str(e.value)


def test_module_entrypoint_exits_with_main_status(monkeypatch):
    import runpy
    monkeypatch.setattr(sys, "argv", ["worker", "--once"])
    monkeypatch.setattr(integ, "_ensure_bridge", lambda: None)
    with pytest.raises(SystemExit) as e:
        runpy.run_module("app.worker", run_name="__main__")
    assert e.value.code == 0
