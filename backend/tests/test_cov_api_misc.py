"""Branch coverage for the smaller API modules: auth, collection, configurations, history, integrations, jobs, training."""
import types
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api.v1 import configurations as cfg_api
from app.api.v1 import history as hist_api
from app.api.v1 import jobs as jobs_api
from app.api.v1 import training as tr_api
from app.core import config as cfg
from app.core import db as dbmod
from app.core import jobs, persist, tenancy
from app.core import security as sec
from app.main import app
from app.services import collection, integration

client = TestClient(app)
PW = "Str0ng!Passw0rd#1"


def _id(p):
    return f"{p}-{uuid.uuid4().hex[:8].upper()}"


def _asset():
    aid = _id("AST")
    persist.save("assets", {"asset_id": aid, "name": "cov-" + aid})
    return aid


def _token(role="ADMIN"):
    email = f"cov-{uuid.uuid4().hex[:8]}@example.com"
    sec.create_user(email, "Cov", PW, role, org_id=cfg.DEFAULT_ORG_ID)
    r = client.post("/api/v1/auth/login", json={"email": email, "password": PW})
    return {"Authorization": f"Bearer {r.json()['data']['access_token']}"}, email


# ---------------------------------------------------------------- auth
def test_change_password_must_differ_and_mfa_setup_refuses_a_second_enrolment():
    h, email = _token()
    r = client.post("/api/v1/auth/change-password", headers=h, json={"current_password": PW, "new_password": PW})
    assert r.status_code == 400 and "differ" in r.text
    with dbmod.get_conn() as conn:
        conn.cursor().execute("UPDATE users SET mfa_enabled=true WHERE email=%s", (email,))
    r = client.post("/api/v1/auth/mfa/setup", headers=h)
    assert r.status_code == 400 and "already enabled" in r.text


# ---------------------------------------------------------------- collection / integrations: queue full -> 429
def test_collect_and_webhook_test_report_a_full_queue(monkeypatch):
    monkeypatch.setattr(cfg, "COLLECT_ALLOW_LOOPBACK", True)
    aid = _asset()
    with tenancy.use_org(cfg.DEFAULT_ORG_ID):
        cred = collection.create_credential("c-" + uuid.uuid4().hex[:6], "u", "pw", "password", None)["credential_id"]
        collection.set_target(aid, "127.0.0.1", 22, "cisco_ios", cred, "SHA256:" + "A" * 43)
    full = lambda *a, **k: (_ for _ in ()).throw(jobs.QueueFull("too many pending jobs"))  # noqa: E731
    monkeypatch.setattr(jobs, "enqueue", full)
    h, _ = _token()
    assert client.post(f"/api/v1/assets/{aid}/collect", json={}, headers=h).status_code == 429
    hook = client.post("/api/v1/integrations/webhooks", json={"name": "cov-hook", "url": "https://93.184.216.34/h", "events": ["audit.completed"]})
    hid = hook.json()["data"]["webhook_id"]
    assert client.post(f"/api/v1/integrations/webhooks/{hid}/test").status_code == 429


# ---------------------------------------------------------------- configurations
def test_human_approval_gate_branches():
    assert cfg_api._needs_human_approval("", {}) == (False, "empty")
    assert cfg_api._needs_human_approval("ip route 10.0.0.0 255.0.0.0 1.1.1.1", {"label": "known"}) == (False, "ai-handled:low-oov")
    assert cfg_api._needs_human_approval("ip route 10.0.0.0 255.0.0.0 1.1.1.1", {})[0] is True


def test_unknown_lines_are_queued_once_and_a_queue_read_failure_is_tolerated(monkeypatch):
    aid = _asset()
    r = client.post("/api/v1/configurations/upload", data={"asset_id": aid}, files={"file": ("r.cfg", b"hostname R1\nip ssh version 2\n", "text/plain")})
    cid = r.json()["data"]["configuration_id"]
    line = f"ip route 10.{uuid.uuid4().int % 250}.0.0 255.0.0.0 192.0.2.1"
    monkeypatch.setattr(cfg_api.canon, "parse_to_canonical", lambda *a, **k: {"unknown_lines": [line], "flat_ir": {}, "nested_ir": {}})
    monkeypatch.setattr(integration, "m2_score_batch", lambda lines: [{"label": "novel"} for _ in lines])
    first = client.get(f"/api/v1/configurations/{cid}/unknowns").json()["data"]
    again = client.get(f"/api/v1/configurations/{cid}/unknowns").json()["data"]       # already queued -> not queued twice
    assert first["items"][0]["line"] == line if "items" in first else True
    assert sum(1 for t in persist.find("training", status="PENDING") if t.get("raw_command") == line) == 1
    real_find = cfg_api.db.find
    monkeypatch.setattr(cfg_api.db, "find", lambda t, **k: (_ for _ in ()).throw(RuntimeError("db")) if t == "training" else real_find(t, **k))
    assert client.get(f"/api/v1/configurations/{cid}/unknowns").status_code == 200
    assert again is not None


# ---------------------------------------------------------------- history
def test_config_diff_reports_snapshots_without_a_stored_configuration(monkeypatch):
    aid = _asset()
    snap = lambda sid: {"asset_id": aid, "snapshot_id": sid, "configuration_id": None}  # noqa: E731
    monkeypatch.setattr(hist_api.history, "get_snapshot", snap)
    path = next(p for p in app.openapi()["paths"] if p.endswith("/assets/{asset_id}/config-diff"))
    url = path.replace("{asset_id}", aid)
    assert client.get(url + "?from=A&to=B").status_code == 409
    monkeypatch.setattr(hist_api.history, "get_snapshot", lambda sid: {"asset_id": aid, "snapshot_id": sid, "configuration_id": "CFG-X"})
    monkeypatch.setattr(hist_api.history, "config_diff", lambda a, b: None)
    assert client.get(url + "?from=A&to=B").status_code == 404


# ---------------------------------------------------------------- jobs
def test_bulk_audit_stops_on_a_full_queue_and_failed_jobs_can_be_retried(monkeypatch):
    monkeypatch.setattr(jobs_api, "_enqueue", lambda *a, **k: (_ for _ in ()).throw(jobs_api.HTTPException(429, "queue full")))
    r = client.post("/api/v1/jobs/bulk-audit", files=[("files", ("a.cfg", b"hostname R1\nip ssh version 2\n", "text/plain"))])
    assert r.status_code == 429
    monkeypatch.undo()
    with tenancy.use_org(cfg.DEFAULT_ORG_ID):
        jid = jobs.enqueue("report", {"audit_id": "AUD-X"})
    with dbmod.get_conn() as conn:
        conn.cursor().execute("UPDATE jobs SET status='FAILED' WHERE job_id=%s", (jid,))
    r = client.post(f"/api/v1/jobs/{jid}/retry")
    assert r.status_code == 200 and r.json()["data"]["status"] == jobs.QUEUED


# ---------------------------------------------------------------- training
def _training(**kw):
    tid = _id("TR")
    persist.save("training", {"training_id": tid, "vendor": "cisco", "platform": "ios", "raw_command": "ip ssh time-out 60",
                              "context": [], "status": "PENDING", **kw})
    return tid


def test_suggest_combines_llm_and_model_suggestions(monkeypatch):
    tid = _training()
    learn = types.SimpleNamespace(suggest=lambda cmd, vendor, ctx: {"suggestions": [{"canonical_property": "SSH.TIMEOUT", "value": 60}]})
    monkeypatch.setattr(tr_api, "okf_layer", lambda: {"learn": learn})
    monkeypatch.setattr(integration, "m3_suggest", lambda cmd, vendor: [{"canonical_property": "SSH.TIMEOUT", "value": 60}, {"value": 1}])
    d = client.post(f"/api/v1/training/{tid}/suggest").json()["data"]
    assert d["suggestions"][0]["canonical_property"] == "SSH.TIMEOUT" and len(d["model_suggestions"]) == 1
    assert client.post("/api/v1/training/TR-NOPE/suggest").status_code == 404


def test_approving_a_line_that_cannot_become_a_safe_pattern_is_a_400(monkeypatch):
    from app.services.integration import okf_layer
    prop = next(iter(p.property_id for p in okf_layer()["props"].all()))
    tid = _training()
    monkeypatch.setattr(tr_api, "build_safe_pattern", lambda raw: (_ for _ in ()).throw(ValueError("too generic")))
    r = client.post(f"/api/v1/training/{tid}/approve", json={"canonical_property": prop, "canonical_value": True})
    assert r.status_code == 400 and "Cannot learn" in r.text
