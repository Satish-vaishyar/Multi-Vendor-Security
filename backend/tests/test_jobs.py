"""Postgres job queue: claiming, retries, recovery, cancel, tenancy, and the bulk-audit / report flows end to end."""
import threading
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import worker
from app.core import config as cfg
from app.core import db as dbmod
from app.core import jobs, rbac, tenancy
from app.core import security as sec
from app.main import app
from app.services import job_handlers

client = TestClient(app)
CORPUS = Path(cfg.OKF_DIR) / "tests" / "corpus"


@pytest.fixture(autouse=True)
def _clean_queue():
    """Each test starts with an empty runnable queue (other suites leave nothing queued, but be explicit)."""
    with dbmod.get_conn() as conn:
        conn.cursor().execute("DELETE FROM jobs WHERE status IN ('QUEUED','RUNNING') AND kind IN ('audit','report')")
    yield


def _sql(q, *a):
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(q, a)
        return cur.fetchall() if cur.description else None


# ----------------------------------------------------------------------------- claiming
def test_concurrent_workers_never_double_claim():
    ids = {jobs.enqueue("report", {"audit_id": f"AUD-{i}"}) for i in range(40)}
    got, lock = [], threading.Lock()

    def worker_thread(n):
        while True:
            j = jobs.claim(f"w{n}")
            if not j:
                return
            with lock:
                got.append(j["job_id"])

    threads = [threading.Thread(target=worker_thread, args=(n,)) for n in range(6)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(got) == sorted(ids)                      # every job claimed ...
    assert len(got) == len(set(got)) == 40                 # ... exactly once, by exactly one worker


def test_priority_then_age_ordering_and_run_after():
    low = jobs.enqueue("report", {"audit_id": "A"})
    time.sleep(0.01)
    high = jobs.enqueue("report", {"audit_id": "B"}, priority=5)
    later = jobs.enqueue("report", {"audit_id": "C"})
    _sql("UPDATE jobs SET run_after = now() + interval '1 hour' WHERE job_id=%s", later)
    assert jobs.claim("w")["job_id"] == high
    assert jobs.claim("w")["job_id"] == low
    assert jobs.claim("w") is None                          # `later` is not due yet


def test_unknown_kind_rejected_and_queue_cap(monkeypatch):
    with pytest.raises(ValueError):
        jobs.enqueue("rm-rf", {})
    monkeypatch.setattr(cfg, "MAX_QUEUED_JOBS_PER_ORG", 2)
    base = _sql("SELECT count(*) FROM jobs WHERE org_id=%s AND status IN ('QUEUED','RUNNING')", tenancy.current_org())[0][0]
    monkeypatch.setattr(cfg, "MAX_QUEUED_JOBS_PER_ORG", base + 1)
    jobs.enqueue("report", {"audit_id": "A"})
    with pytest.raises(jobs.QueueFull):
        jobs.enqueue("report", {"audit_id": "B"})


# ------------------------------------------------------------------------ retry / recovery
def test_transient_failure_retries_with_backoff_then_fails(monkeypatch):
    calls = {"n": 0}

    def flaky(job):
        calls["n"] += 1
        raise RuntimeError("database blip")

    monkeypatch.setitem(job_handlers.HANDLERS, "report", flaky)
    jid = jobs.enqueue("report", {"audit_id": "X"}, max_attempts=3)
    assert worker.process_one("w1") is True
    j = jobs.get(jid)
    assert j["status"] == jobs.QUEUED and j["attempts"] == 1 and "database blip" in j["error"]
    assert j["run_after"] > time.time() + 3                 # backed off (5 s), so it is not immediately runnable
    assert worker.process_one("w1") is False
    for expected_attempt in (2, 3):
        _sql("UPDATE jobs SET run_after = now() WHERE job_id=%s", jid)
        assert worker.process_one("w1") is True
        assert jobs.get(jid)["attempts"] == expected_attempt
    j = jobs.get(jid)
    assert j["status"] == jobs.FAILED and calls["n"] == 3 and j["finished_at"]


def test_permanent_error_is_not_retried():
    jid = jobs.enqueue("audit", {"configuration_id": "CFG-DOES-NOT-EXIST", "asset_id": "AST-X"})
    worker.process_one("w1")
    j = jobs.get(jid)
    assert j["status"] == jobs.FAILED and j["attempts"] == 1 and "configuration not found" in j["error"]
    assert jobs.retry(jid) is True                          # an operator can re-queue it explicitly
    assert jobs.get(jid)["status"] == jobs.QUEUED and jobs.get(jid)["attempts"] == 0
    assert jobs.retry(jid) is False                         # but not while it is queued


def test_crashed_worker_jobs_are_recovered():
    a = jobs.enqueue("report", {"audit_id": "A"})
    b = jobs.enqueue("report", {"audit_id": "B"}, max_attempts=1)
    jobs.claim("dead-worker")
    jobs.claim("dead-worker")
    _sql("UPDATE jobs SET locked_at = now() - interval '2 hours' WHERE job_id IN (%s,%s)", a, b)
    assert jobs.requeue_stale(900) == 2
    assert jobs.get(a)["status"] == jobs.QUEUED            # attempts left -> back in the queue
    assert jobs.get(b)["status"] == jobs.FAILED            # out of attempts -> failed, not lost
    assert jobs.requeue_stale(900) == 0                    # a healthy running job is left alone
    jobs.claim("w")
    assert jobs.requeue_stale(900) == 0


def test_late_completion_from_a_replaced_worker_is_ignored():
    jid = jobs.enqueue("report", {"audit_id": "A"})
    jobs.claim("slow")
    _sql("UPDATE jobs SET locked_at = now() - interval '2 hours' WHERE job_id=%s", jid)
    jobs.requeue_stale(900)
    jobs.claim("fast")
    jobs.complete(jid, "slow", {"stale": True})              # the old worker finally finishes: must not win
    assert jobs.get(jid)["status"] == jobs.RUNNING
    jobs.complete(jid, "fast", {"ok": True})
    assert jobs.get(jid)["status"] == jobs.COMPLETED and jobs.get(jid)["result"] == {"ok": True}


# ----------------------------------------------------------------------------------- cancel
def test_cancel_queued_and_running():
    q = jobs.enqueue("report", {"audit_id": "A"})
    assert jobs.cancel(q) == jobs.CANCELLED and jobs.get(q)["status"] == jobs.CANCELLED
    assert worker.process_one("w") is False                 # a cancelled job is never picked up
    r = jobs.enqueue("report", {"audit_id": "B"})
    jobs.claim("w1")
    assert jobs.cancel(r) == jobs.RUNNING
    assert jobs.heartbeat(r, "w1") is False                 # the worker sees the request at its next checkpoint
    jobs.mark_cancelled(r, "w1")
    assert jobs.get(r)["status"] == jobs.CANCELLED
    assert jobs.cancel(r) is None and jobs.cancel("JOB-NOPE") is None
    assert jobs.retry(r) is True                            # cancelled jobs can be re-queued


def test_purge_only_removes_old_finished_jobs():
    old = jobs.enqueue("report", {"audit_id": "A"})
    keep = jobs.enqueue("report", {"audit_id": "B"})
    jobs.cancel(old)
    _sql("UPDATE jobs SET finished_at = now() - interval '90 days' WHERE job_id=%s", old)
    assert jobs.purge(30) >= 1
    assert jobs.get(old) is None and jobs.get(keep)["status"] == jobs.QUEUED


# ----------------------------------------------------------------------------------- tenancy
def test_jobs_are_tenant_isolated_and_run_in_their_own_org():
    for org in ("ORG-J1", "ORG-J2"):
        _sql("INSERT INTO organizations (org_id,name) VALUES (%s,%s) ON CONFLICT DO NOTHING", org, org)
    with tenancy.use_org("ORG-J1"):
        jid = jobs.enqueue("report", {"audit_id": "A"})
        assert jobs.get(jid) and jobs.list_jobs(limit=500)
    with tenancy.use_org("ORG-J2"):
        assert jobs.get(jid) is None                        # invisible
        assert jobs.cancel(jid) is None and jobs.retry(jid) is False
        assert jid not in {j["job_id"] for j in jobs.list_jobs(limit=500)}
        assert jobs.batch_summary("BATCH-X") is None
    claimed = jobs.claim("w")                               # the worker is cross-tenant and gets the job's org
    assert claimed["org_id"] == "ORG-J1"


# ------------------------------------------------------------------------- end-to-end via HTTP
def _upload_files(names):
    return [("files", (n, (CORPUS / n).read_bytes(), "text/plain")) for n in names]


def test_bulk_audit_runs_a_whole_fleet_in_the_background():
    names = ["cisco_iosxe_core_hardened.cfg", "junos_ex_access_mixed.cfg", "fortios_fg100f_edge.cfg", "arista_eos_leaf.cfg"]
    files = _upload_files(names) + [("files", ("empty.cfg", b"   \n", "text/plain"))]
    r = client.post("/api/v1/jobs/bulk-audit", files=files, data={"frameworks": "CIS,NIST", "run_cve": "false"})
    assert r.status_code == 202, r.text
    d = r.json()["data"]
    assert d["accepted"] == 4 and len(d["rejected"]) == 1 and d["rejected"][0]["filename"] == "empty.cfg"
    devices = {j["device"] for j in d["jobs"]}
    assert {"CORE-RTR-01", "ex4300-access-07", "FGT-EDGE-01", "leaf-12"} <= devices     # named from each config's hostname
    batch = client.get(f"/api/v1/jobs/batches/{d['batch_id']}").json()["data"]
    assert batch["total"] == 4 and batch["counts"] == {"QUEUED": 4} and batch["state"] == "RUNNING"
    assert worker.drain() == 4
    batch = client.get(f"/api/v1/jobs/batches/{d['batch_id']}").json()["data"]
    assert batch["state"] == "COMPLETED" and batch["progress_pct"] == 100.0 and batch["counts"] == {"COMPLETED": 4}
    for j in d["jobs"]:
        job = client.get(f"/api/v1/jobs/{j['job_id']}").json()["data"]
        assert job["status"] == "COMPLETED" and job["progress"] == 100 and job["result"]["audit_id"]
        res = client.get(f"/api/v1/audits/{job['result']['audit_id']}/results").json()["data"]
        assert res["assessment"]["parser"]["used"] is True and res["status"] == "COMPLETED"
    hardened = next(client.get(f"/api/v1/jobs/{j['job_id']}").json()["data"] for j in d["jobs"] if j["device"] == "CORE-RTR-01")
    assert hardened["result"]["compliance_score"] >= 90
    # re-submitting the same fleet re-uses the assets and the (deterministic) audits - no duplicates
    r2 = client.post("/api/v1/jobs/bulk-audit", files=_upload_files(names[:2]), data={"run_cve": "false"}).json()["data"]
    assert {j["asset_id"] for j in r2["jobs"]} == {j["asset_id"] for j in d["jobs"] if j["filename"] in names[:2]}
    worker.drain()
    ids2 = {client.get(f"/api/v1/jobs/{j['job_id']}").json()["data"]["result"]["audit_id"] for j in r2["jobs"]}
    ids1 = {client.get(f"/api/v1/jobs/{j['job_id']}").json()["data"]["result"]["audit_id"] for j in d["jobs"] if j["filename"] in names[:2]}
    assert ids1 == ids2


def test_bulk_audit_validation():
    assert client.post("/api/v1/jobs/bulk-audit", files=[("files", ("e.cfg", b"", "text/plain"))]).status_code == 400
    ok = _upload_files(["cisco_iosxe_core_hardened.cfg"])
    assert client.post("/api/v1/jobs/bulk-audit", files=ok, data={"frameworks": "NOPE"}).status_code == 400
    assert client.post("/api/v1/jobs/bulk-audit", files=ok, data={"criticality": "WHATEVER"}).status_code == 400
    old = cfg.MAX_BATCH_FILES
    cfg.MAX_BATCH_FILES = 1
    try:
        assert client.post("/api/v1/jobs/bulk-audit", files=_upload_files(["cisco_iosxe_core_hardened.cfg"] * 2)).status_code == 400
    finally:
        cfg.MAX_BATCH_FILES = old


def test_single_audit_and_report_jobs_via_api():
    asset = client.post("/api/v1/assets", json={"name": f"job-{uuid.uuid4().hex[:6]}"}).json()["data"]["asset_id"]
    cid = client.post("/api/v1/configurations/upload", data={"asset_id": asset},
                      files={"file": ("c.cfg", (CORPUS / "panos_pa850_set.cfg").read_bytes(), "text/plain")}).json()["data"]["configuration_id"]
    assert client.post("/api/v1/jobs/audit", json={"asset_id": asset, "configuration_id": "CFG-NOPE"}).status_code == 404
    assert client.post("/api/v1/jobs/audit", json={"asset_id": "AST-NOPE", "configuration_id": cid}).status_code == 404
    assert client.post("/api/v1/jobs/audit", json={"asset_id": asset, "configuration_id": cid, "frameworks": ["BOGUS"]}).status_code == 400
    j = client.post("/api/v1/jobs/audit", json={"asset_id": asset, "configuration_id": cid, "run_cve": False})
    assert j.status_code == 202
    jid = j.json()["data"]["job_id"]
    assert client.get(f"/api/v1/jobs/{jid}").json()["data"]["status"] == "QUEUED"
    assert any(x["job_id"] == jid for x in client.get("/api/v1/jobs?status=queued&kind=audit").json()["data"]["items"])
    worker.drain()
    done = client.get(f"/api/v1/jobs/{jid}").json()["data"]
    assert done["status"] == "COMPLETED"
    assert client.post("/api/v1/jobs/report", json={"audit_id": "AUD-NOPE"}).status_code == 404
    rj = client.post("/api/v1/jobs/report", json={"audit_id": done["result"]["audit_id"]}).json()["data"]["job_id"]
    worker.drain()
    rres = client.get(f"/api/v1/jobs/{rj}").json()["data"]
    assert rres["status"] == "COMPLETED"
    pdf = client.get(rres["result"]["download_url"])
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert client.get("/api/v1/jobs/JOB-NOPE").status_code == 404
    assert client.get("/api/v1/jobs/batches/BATCH-NOPE").status_code == 404
    assert client.post("/api/v1/jobs/JOB-NOPE/cancel").status_code == 409
    assert client.post(f"/api/v1/jobs/{jid}/retry").status_code == 409          # completed jobs are not retryable
    assert client.get(f"/api/v1/training/jobs/{jid}").status_code == 200        # legacy job endpoint sees queue jobs too


def test_queue_full_returns_429(monkeypatch):
    base = _sql("SELECT count(*) FROM jobs WHERE org_id=%s AND status IN ('QUEUED','RUNNING')", tenancy.current_org())[0][0]
    monkeypatch.setattr(cfg, "MAX_QUEUED_JOBS_PER_ORG", base)
    assert client.post("/api/v1/jobs/report", json={"audit_id": "AUD-X"}).status_code in (404, 429)
    asset = client.post("/api/v1/assets", json={"name": f"full-{uuid.uuid4().hex[:6]}"}).json()["data"]["asset_id"]
    cid = client.post("/api/v1/configurations/upload", data={"asset_id": asset},
                      files={"file": ("c.cfg", b"hostname R1\nip ssh version 2\n", "text/plain")}).json()["data"]["configuration_id"]
    assert client.post("/api/v1/jobs/audit", json={"asset_id": asset, "configuration_id": cid}).status_code == 429


# ---------------------------------------------------------------------------- worker process
def test_worker_main_once_and_embedded_worker_toggle(capsys):
    jobs.enqueue("report", {"audit_id": "AUD-NOPE"})
    assert worker.main(["--once"]) == 0
    assert "processed 1 job" in capsys.readouterr().out
    stop = threading.Event()
    t = threading.Thread(target=worker.run_forever, args=(stop, 0.05), daemon=True)
    t.start()
    jid = jobs.enqueue("report", {"audit_id": "AUD-NOPE"})
    for _ in range(600):
        if jobs.get(jid)["status"] == jobs.FAILED:
            break
        time.sleep(0.1)
    stop.set()
    t.join(timeout=90)
    assert jobs.get(jid)["status"] == jobs.FAILED and "audit not found" in jobs.get(jid)["error"]
    assert not t.is_alive()


def test_handler_without_registration_fails_permanently(monkeypatch):
    jid = jobs.enqueue("report", {"audit_id": "A"})
    monkeypatch.delitem(job_handlers.HANDLERS, "report")
    worker.process_one("w")
    assert jobs.get(jid)["status"] == jobs.FAILED and "no handler" in jobs.get(jid)["error"]


# --------------------------------------------------------------------------------- RBAC / tenancy over HTTP
def test_rbac_and_tenant_isolation_over_http(monkeypatch):
    monkeypatch.setattr(cfg, "REQUIRE_AUTH", True)
    sec.reset_throttle()
    for org in ("ORG-H1", "ORG-H2"):
        _sql("INSERT INTO organizations (org_id,name) VALUES (%s,%s) ON CONFLICT DO NOTHING", org, org)

    def hdr(role, org):
        email = f"{role.lower()}-{uuid.uuid4().hex[:6]}@example.com"
        sec.create_user(email, role, "Str0ng!Passw0rd#1", role, org_id=org)
        t = client.post("/api/v1/auth/login", json={"email": email, "password": "Str0ng!Passw0rd#1"}).json()["data"]["access_token"]
        return {"Authorization": f"Bearer {t}"}

    viewer, auditor1, auditor2 = hdr(rbac.VIEWER, "ORG-H1"), hdr(rbac.AUDITOR, "ORG-H1"), hdr(rbac.AUDITOR, "ORG-H2")
    assert client.post("/api/v1/jobs/report", headers=viewer, json={"audit_id": "A"}).status_code == 403
    assert client.get("/api/v1/jobs", headers=viewer).status_code == 200
    with tenancy.use_org("ORG-H1"):
        jid = jobs.enqueue("report", {"audit_id": "A"})
    assert client.get(f"/api/v1/jobs/{jid}", headers=auditor1).status_code == 200
    assert client.get(f"/api/v1/jobs/{jid}", headers=auditor2).status_code == 404
    assert client.post(f"/api/v1/jobs/{jid}/cancel", headers=auditor2).status_code == 409
    assert client.post(f"/api/v1/jobs/{jid}/cancel", headers=viewer).status_code == 403
    assert client.post(f"/api/v1/jobs/{jid}/cancel", headers=auditor1).status_code == 200


def test_cve_auto_sync_off_by_default_and_single_flight(monkeypatch):
    import time
    from app import worker
    from app.core import config as cfg
    assert worker.cve_auto_sync() is None                      # CVE_AUTO_SYNC_HOURS=0 -> disabled
    monkeypatch.setattr(cfg, "CVE_AUTO_SYNC_HOURS", 1.0)
    monkeypatch.setattr(worker, "_cve_last_sync", 0.0)
    calls = []
    import app.services.integration as integ
    monkeypatch.setattr(integ, "cve_layer", lambda: {"sync_now": lambda *a, **k: calls.append(k) or {"ok": True}})
    import src.cve.kev as kev
    monkeypatch.setattr(kev, "sync_kev", lambda: {"ok": True})
    assert worker.cve_auto_sync() == {"started": True}
    assert worker.cve_auto_sync() is None                      # interval not elapsed
    for _ in range(50):
        if calls:
            break
        time.sleep(0.05)
    assert calls and calls[0]["since_days"] == cfg.CVE_AUTO_SYNC_DAYS
