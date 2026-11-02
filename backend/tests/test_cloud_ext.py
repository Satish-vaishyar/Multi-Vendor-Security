"""Cloud module extras (docs/CLOUD_MODULE_RTM.md S23): kept files, recurring scans, webhook links, asset links. Runs against the
real test database (the scanner service is faked); the existing schedules/webhooks/assets modules are used only to create the rows
that the cloud tables reference."""
import uuid

import psycopg
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app import cloud_scheduler
from app.api.v1 import cloud
from app.core import auditlog, cloud_runner, cloud_store, crypto, jobs, tenancy, webhooks
from app.core import cloud_ext as ext
from app.core import config as cfg
from app.core import db as dbmod
from app.core import security as sec

app = FastAPI()
app.include_router(cloud.router)
client = TestClient(app)
ROLE = {"role": "ADMIN"}
SCANNER = {"report": None}
app.dependency_overrides[sec.require_user] = lambda: {"email": "t@example.com", "id": "USR-T", **ROLE}
CLEAN = {"status": "COMPLETED", "summary": {"states": {"PASS_STATIC": 1}}, "statement": "s", "coverage": {"providers": ["aws"]},
         "findings": [], "resources": [], "input": {"filename": "a.tf", "sha256": "0" * 64, "size_bytes": 3}}
SECRET = {**CLEAN, "findings": [{"control_id": "CLOUD-SEC-001", "title": "secret", "severity": "HIGH", "evidence_state": "FAIL_STATIC"}]}
OTHER_ORG = "ORG-CLOUDEXT"


class FakeResponse:
    def __init__(self, status=200, body=None):
        self.status_code, self._body = status, body

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("CLOUD_MODULE_ENABLED", "true")
    monkeypatch.setattr(auditlog, "record", lambda *a, **k: None)
    SCANNER["report"] = CLEAN
    monkeypatch.setattr(cloud, "_scanner_post", lambda *a, **k: FakeResponse(200, SCANNER["report"]))
    ROLE["role"] = "ADMIN"
    yield
    with dbmod.get_conn() as conn:
        c = conn.cursor()
        for t in ("cloud_schedules", "cloud_sources", "cloud_webhook_links", "cloud_asset_links"):
            c.execute(f"DELETE FROM {t}")
        c.execute("DELETE FROM cloud_scans WHERE scan_id LIKE 'CSCAN-%%'")
        c.execute("DELETE FROM webhooks WHERE name LIKE 'cloudext-%%'")
        c.execute("DELETE FROM assets WHERE asset_id LIKE 'AST-CLOUDEXT-%%'")
        c.execute("DELETE FROM jobs WHERE created_by = 'cloud'")


def _scan(org=None) -> str:
    sid = "CSCAN-" + uuid.uuid4().hex[:16]
    if org:
        with tenancy.use_org(org):
            cloud_store.save_report(sid, CLEAN, "t")
    else:
        cloud_store.save_report(sid, CLEAN, "t")
    return sid


def _kept(data=b"resource x {}") -> str:
    sid = _scan()
    ext.retain_source(sid, "a.tf", data, "t")
    return sid


def _asset(name="srv") -> str:
    aid = "AST-CLOUDEXT-" + uuid.uuid4().hex[:8]
    with dbmod.get_conn() as conn:
        conn.cursor().execute("INSERT INTO assets (asset_id, name) VALUES (%s,%s)", [aid, name])
    return aid


def _hook(fmt="json", enabled=True) -> str:
    h = webhooks.create("cloudext-" + uuid.uuid4().hex[:6], "http://127.0.0.1:9/hook", ["ping"], fmt, "t")
    if not enabled:
        webhooks.update(h["webhook_id"], enabled=False)
    return h["webhook_id"]


def _other_org():
    with dbmod.get_conn() as conn:
        conn.cursor().execute("INSERT INTO organizations (org_id, name) VALUES (%s,%s) ON CONFLICT DO NOTHING", [OTHER_ORG, "cloudext"])


# ------------------------------------------------------------------------------------------------ kept files
def test_kept_file_roundtrip_is_encrypted_and_bounded():
    sid = _scan()
    src_id = ext.retain_source(sid, "main.tf", b"secret-looking? no: plain bytes \x00\xff", "t")
    meta = ext.source_for_scan(sid)
    assert meta["source_id"] == src_id and meta["size_bytes"] == len(b"secret-looking? no: plain bytes \x00\xff")
    assert ext.load_source(src_id)["data"] == b"secret-looking? no: plain bytes \x00\xff"
    with dbmod.get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT content_enc FROM cloud_sources WHERE source_id=%s", [src_id])
        enc = c.fetchone()[0]
    assert crypto.is_encrypted(enc) and "plain bytes" not in enc
    with pytest.raises(ext.ExtError):
        ext.retain_source(sid, "big.tf", b"x" * (ext.MAX_SOURCE_BYTES + 1), "t")
    with pytest.raises(ext.ExtError):
        ext.retain_source("CSCAN-" + "0" * 16, "a.tf", b"x", "t")
    assert ext.delete_source(sid) and not ext.delete_source(sid) and ext.source_for_scan(sid) is None and ext.load_source(src_id) is None


def test_kept_file_cap_expiry_and_isolation(monkeypatch):
    monkeypatch.setattr(ext, "MAX_SOURCES_PER_ORG", 2)
    first, second = _kept(), _kept()
    with pytest.raises(ext.ExtError):
        ext.retain_source(_scan(), "c.tf", b"x", "t")
    with dbmod.get_conn() as conn:                      # an expired copy is purged and frees its slot
        conn.cursor().execute("UPDATE cloud_sources SET expires_at = now() - interval '1 day' WHERE scan_id=%s", [first])
    assert ext.source_for_scan(first) is None
    ext.retain_source(_scan(), "c.tf", b"x", "t")
    _other_org()
    with tenancy.use_org(OTHER_ORG):
        assert ext.source_for_scan(second) is None and not ext.delete_source(second)
    with dbmod.get_conn() as conn:
        conn.cursor().execute("UPDATE cloud_sources SET expires_at = now() - interval '1 day'")
    assert ext.purge_expired_sources() >= 1


# --------------------------------------------------------------------------------------------------- schedules
def test_schedule_lifecycle_and_validation(monkeypatch):
    sid = _kept()
    s = ext.create_schedule(sid, "", 60, "t")
    assert s["name"] == "a.tf" and s["enabled"] and s["next_run_at"] > 0 and ext.get_schedule(s["schedule_id"]) == s
    assert [x["schedule_id"] for x in ext.list_schedules()] == [s["schedule_id"]]
    for bad in (59, ext.MAX_INTERVAL_MINUTES + 1, True, "60"):
        with pytest.raises(ext.ExtError):
            ext.create_schedule(sid, "x", bad, "t")        # type: ignore[arg-type]
    with pytest.raises(ext.ExtError):
        ext.create_schedule(_scan(), "x", 60, "t")         # no kept file
    off = ext.update_schedule(s["schedule_id"], enabled=False)
    assert off["enabled"] is False
    assert ext.update_schedule(s["schedule_id"], enabled=True, interval_minutes=120)["interval_minutes"] == 120
    assert ext.update_schedule(s["schedule_id"])["schedule_id"] == s["schedule_id"]       # no-op patch
    assert ext.update_schedule("CSCH-" + "0" * 12, enabled=True) is None
    with pytest.raises(ext.ExtError):
        ext.update_schedule(s["schedule_id"], interval_minutes=1)
    monkeypatch.setattr(ext, "MAX_SCHEDULES_PER_ORG", 1)
    with pytest.raises(ext.ExtError):
        ext.create_schedule(sid, "again", 60, "t")
    assert ext.delete_schedule(s["schedule_id"]) and not ext.delete_schedule(s["schedule_id"])


def test_claim_due_advances_before_running_and_skips_disabled_and_expired():
    due, off, gone = _kept(), _kept(), _kept()
    a, b, c = (ext.create_schedule(x, "n", 60, "t") for x in (due, off, gone))
    ext.update_schedule(b["schedule_id"], enabled=False)
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE cloud_schedules SET next_run_at = now() - interval '1 minute'")
        cur.execute("UPDATE cloud_sources SET expires_at = now() - interval '1 day' WHERE scan_id=%s", [gone])
    rows = ext.claim_due(10)
    assert [r["schedule_id"] for r in rows] == [a["schedule_id"]] and rows[0]["org_id"] == cfg.DEFAULT_ORG_ID
    assert ext.claim_due(10) == []                                          # already advanced: no second claim
    assert ext.get_schedule(a["schedule_id"])["next_run_at"] > ext.get_schedule(a["schedule_id"])["last_run_at"]
    assert ext.get_schedule(c["schedule_id"])["last_status"] == "SOURCE_EXPIRED" and not ext.get_schedule(c["schedule_id"])["enabled"]
    ext.record_run(a["schedule_id"], "CSCAN-x", "COMPLETED")
    assert ext.get_schedule(a["schedule_id"])["last_status"] == "COMPLETED"


# --------------------------------------------------------------------------------------------- webhook links
def test_webhook_links_and_emit():
    on, off, slack = _hook(), _hook(enabled=False), _hook("slack")
    for bad_events in ([], ["audit.completed"], ["cloud.scan.completed", "nope"]):
        with pytest.raises(ext.ExtError):
            ext.link_webhook(on, bad_events, "t")
    with pytest.raises(ext.ExtError):
        ext.link_webhook("WHK-0000000000", ["cloud.scan.completed"], "t")
    with pytest.raises(ext.ExtError):
        ext.link_webhook(slack, ["cloud.scan.completed"], "t")
    ext.link_webhook(on, ["cloud.scan.completed"], "t")
    ext.link_webhook(off, ["cloud.scan.completed"], "t")
    assert ext.link_webhook(on, ["cloud.scan.failed", "cloud.scan.completed"], "t")["events"] == ["cloud.scan.completed", "cloud.scan.failed"]
    assert {x["webhook_id"] for x in ext.list_webhook_links()} == {on, off}
    assert ext.emit("audit.completed", {}) == 0                              # not a cloud event
    assert ext.emit("cloud.scan.completed", {"scan_id": "CSCAN-1"}) == 1     # disabled hook is skipped
    with dbmod.get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT kind, payload FROM jobs WHERE created_by='cloud'")
        kind, payload = c.fetchone()
    assert kind == "webhook" and payload["webhook_id"] == on and payload["event"] == "cloud.scan.completed"
    assert ext.unlink_webhook(on) and not ext.unlink_webhook(on)
    assert ext.emit("cloud.scan.completed", {}) == 0


def test_emit_never_raises(monkeypatch):
    on = _hook()
    ext.link_webhook(on, ["cloud.scan.completed"], "t")
    monkeypatch.setattr(jobs, "enqueue", lambda *a, **k: (_ for _ in ()).throw(jobs.QueueFull("full")))
    assert ext.emit("cloud.scan.completed", {}) == 0


# ------------------------------------------------------------------------------------------------ asset links
def test_asset_links_are_opt_in_idempotent_and_tenant_scoped():
    sid, aid = _scan(), _asset("core-sw")
    assert ext.links_for_scan(sid) == [] and ext.links_for_asset(aid) == []
    assert ext.link_asset(sid, aid, "t")["asset_name"] == "core-sw"
    ext.link_asset(sid, aid, "t")                                            # idempotent
    assert [x["asset_id"] for x in ext.links_for_scan(sid)] == [aid]
    assert [x["scan_id"] for x in ext.links_for_asset(aid)] == [sid]
    with pytest.raises(ext.ExtError):
        ext.link_asset(sid, "AST-CLOUDEXT-none", "t")
    with pytest.raises(ext.ExtError):
        ext.link_asset("CSCAN-" + "0" * 16, aid, "t")
    _other_org()
    with tenancy.use_org(OTHER_ORG):
        with pytest.raises(ext.ExtError):
            ext.link_asset(sid, aid, "t")
        assert ext.links_for_scan(sid) == [] and not ext.unlink_asset(sid, aid)
    with dbmod.get_conn() as conn:                                           # the asset row itself is never modified
        c = conn.cursor()
        c.execute("SELECT name FROM assets WHERE asset_id=%s", [aid])
        assert c.fetchone()[0] == "core-sw"
    assert ext.unlink_asset(sid, aid) and not ext.unlink_asset(sid, aid)


# ----------------------------------------------------------------------------------------------------- API
def _upload(retain=True, report=CLEAN):
    SCANNER["report"] = report
    return client.post(f"/api/v1/cloud/scans?retain={'true' if retain else 'false'}", files={"file": ("a.tf", b"resource x {}")})


def test_upload_keeps_file_only_on_request_and_never_with_a_secret(monkeypatch):
    r = _upload(retain=True)
    assert r.status_code == 201 and r.json()["data"]["retention"] == {"kept": True}
    scan_id = r.json()["data"]["scan_id"]
    assert client.get(f"/api/v1/cloud/scans/{scan_id}/source").json()["data"]["kept"] is True
    assert _upload(retain=False).json()["data"]["retention"] is None
    refused = _upload(retain=True, report=SECRET).json()["data"]
    assert refused["retention"]["kept"] is False and "secret" in refused["retention"]["reason"]
    assert _upload(retain=True, report={**CLEAN, "status": "FAILED"}).json()["data"]["retention"]["kept"] is False
    monkeypatch.setattr(ext, "MAX_SOURCES_PER_ORG", 1)
    assert "at most" in _upload(retain=True).json()["data"]["retention"]["reason"]
    assert client.delete(f"/api/v1/cloud/scans/{scan_id}/source").status_code == 200
    assert client.delete(f"/api/v1/cloud/scans/{scan_id}/source").status_code == 404
    assert client.get(f"/api/v1/cloud/scans/{scan_id}/source").json()["data"] == {"kept": False, "expires_at": None}


def test_schedule_api_roles_validation_and_run_now(monkeypatch):
    scan_id = _upload().json()["data"]["scan_id"]
    ROLE["role"] = "VIEWER"
    assert client.post("/api/v1/cloud/schedules", json={"scan_id": scan_id, "interval_minutes": 60}).status_code == 403
    assert client.get("/api/v1/cloud/schedules").json()["data"]["limits"]["min_interval_minutes"] == 60
    ROLE["role"] = "AUDITOR"
    assert client.post("/api/v1/cloud/schedules", json={"scan_id": scan_id, "interval_minutes": 5}).status_code == 422
    assert client.post("/api/v1/cloud/schedules", json={"scan_id": "bad", "interval_minutes": 60}).status_code == 404
    assert client.post("/api/v1/cloud/schedules", json={"scan_id": _scan(), "interval_minutes": 60}).status_code == 400
    s = client.post("/api/v1/cloud/schedules", json={"scan_id": scan_id, "interval_minutes": 60, "name": "nightly"})
    assert s.status_code == 201
    sid = s.json()["data"]["schedule_id"]
    assert client.patch(f"/api/v1/cloud/schedules/{sid}", json={"enabled": False}).json()["data"]["enabled"] is False
    assert client.patch(f"/api/v1/cloud/schedules/{sid}", json={"interval_minutes": 1}).status_code == 422
    assert client.patch("/api/v1/cloud/schedules/CSCH-000000000000", json={"enabled": True}).status_code == 404
    with monkeypatch.context() as m:
        m.setattr(ext, "update_schedule", lambda *a, **k: (_ for _ in ()).throw(ext.ExtError("rejected")))
        assert client.patch(f"/api/v1/cloud/schedules/{sid}", json={"enabled": True}).status_code == 400
    assert client.patch("/api/v1/cloud/schedules/nope", json={"enabled": True}).status_code == 404
    run = client.post(f"/api/v1/cloud/schedules/{sid}/run").json()["data"]
    assert run["status"] == "COMPLETED" and run["scan_id"].startswith("CSCAN-")
    assert ext.get_schedule(sid)["last_scan_id"] == run["scan_id"]
    assert client.post("/api/v1/cloud/schedules/CSCH-000000000000/run").status_code == 404
    assert client.delete(f"/api/v1/cloud/schedules/{sid}").status_code == 200
    assert client.delete(f"/api/v1/cloud/schedules/{sid}").status_code == 404
    assert client.delete("/api/v1/cloud/schedules/nope").status_code == 404


def test_schedule_api_cascades_when_the_kept_file_is_deleted():
    scan_id = _upload().json()["data"]["scan_id"]
    sid = client.post("/api/v1/cloud/schedules", json={"scan_id": scan_id, "interval_minutes": 60}).json()["data"]["schedule_id"]
    client.delete(f"/api/v1/cloud/scans/{scan_id}/source")
    assert ext.get_schedule(sid) is None


def test_webhook_link_api_needs_admin_and_validates():
    hook = _hook()
    ROLE["role"] = "AUDITOR"
    assert client.put(f"/api/v1/cloud/webhook-links/{hook}", json={"events": ["cloud.scan.completed"]}).status_code == 403
    assert client.delete(f"/api/v1/cloud/webhook-links/{hook}").status_code == 403
    assert client.get("/api/v1/cloud/webhook-links").json()["data"]["events"] == list(ext.CLOUD_EVENTS)
    ROLE["role"] = "ADMIN"
    assert client.put("/api/v1/cloud/webhook-links/nope", json={"events": ["cloud.scan.completed"]}).status_code == 404
    assert client.put(f"/api/v1/cloud/webhook-links/{hook}", json={"events": ["x"]}).status_code == 400
    assert client.put(f"/api/v1/cloud/webhook-links/{hook}", json={"events": []}).status_code == 422
    ok = client.put(f"/api/v1/cloud/webhook-links/{hook}", json={"events": ["cloud.scan.completed"]})
    assert ok.status_code == 200 and client.get("/api/v1/cloud/webhook-links").json()["data"]["items"][0]["webhook_id"] == hook
    _upload(retain=False)                               # a completed scan now queues one delivery on the linked hook
    with dbmod.get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT count(*) FROM jobs WHERE created_by='cloud' AND kind='webhook'")
        assert c.fetchone()[0] == 1
    assert client.delete(f"/api/v1/cloud/webhook-links/{hook}").status_code == 200
    assert client.delete(f"/api/v1/cloud/webhook-links/{hook}").status_code == 404
    assert client.delete("/api/v1/cloud/webhook-links/nope").status_code == 404


def test_asset_link_api():
    scan_id, aid = _scan(), _asset()
    ROLE["role"] = "VIEWER"
    assert client.post(f"/api/v1/cloud/scans/{scan_id}/assets", json={"asset_id": aid}).status_code == 403
    ROLE["role"] = "AUDITOR"
    assert client.post(f"/api/v1/cloud/scans/{scan_id}/assets", json={"asset_id": "bad id!"}).status_code == 400
    assert client.post(f"/api/v1/cloud/scans/{scan_id}/assets", json={"asset_id": "AST-CLOUDEXT-none"}).status_code == 400
    assert client.post("/api/v1/cloud/scans/nope/assets", json={"asset_id": aid}).status_code == 404
    assert client.post(f"/api/v1/cloud/scans/{scan_id}/assets", json={"asset_id": aid}).status_code == 201
    assert client.get(f"/api/v1/cloud/scans/{scan_id}/assets").json()["data"]["items"][0]["asset_id"] == aid
    assert client.get(f"/api/v1/cloud/assets/{aid}/scans").json()["data"]["items"][0]["scan_id"] == scan_id
    assert client.get("/api/v1/cloud/assets/bad id!/scans").status_code == 404
    assert client.delete(f"/api/v1/cloud/scans/{scan_id}/assets/{aid}").status_code == 200
    assert client.delete(f"/api/v1/cloud/scans/{scan_id}/assets/{aid}").status_code == 404
    assert client.delete(f"/api/v1/cloud/scans/{scan_id}/assets/bad id!").status_code == 404


def test_new_routes_are_hidden_when_the_module_is_off(monkeypatch):
    monkeypatch.setenv("CLOUD_MODULE_ENABLED", "")
    sid = "CSCAN-0123456789abcdef"
    for method, path in (("get", "/schedules"), ("post", "/schedules"), ("patch", "/schedules/CSCH-000000000000"),
                         ("delete", "/schedules/CSCH-000000000000"), ("post", "/schedules/CSCH-000000000000/run"),
                         ("get", f"/scans/{sid}/source"), ("delete", f"/scans/{sid}/source"), ("get", "/webhook-links"),
                         ("put", "/webhook-links/WHK-0000000000"), ("delete", "/webhook-links/WHK-0000000000"),
                         ("get", f"/scans/{sid}/assets"), ("post", f"/scans/{sid}/assets"),
                         ("delete", f"/scans/{sid}/assets/a"), ("get", "/assets/a/scans")):
        kw = {"json": {"scan_id": sid, "interval_minutes": 60, "events": ["cloud.scan.completed"], "enabled": True, "asset_id": "a"}} \
            if method in ("post", "put", "patch") else {}
        assert getattr(client, method)("/api/v1/cloud" + path, **kw).status_code == 404, (method, path)


# --------------------------------------------------------------------------------------------------- runner
def test_runner_runs_due_schedules_once_and_isolates_failures(monkeypatch):
    good, missing = _kept(), _kept()
    g, m = ext.create_schedule(good, "g", 60, "t"), ext.create_schedule(missing, "m", 60, "t")
    with dbmod.get_conn() as conn:
        c = conn.cursor()
        c.execute("UPDATE cloud_schedules SET next_run_at = now() - interval '1 minute'")
        c.execute("DELETE FROM cloud_sources WHERE scan_id=%s", [missing])         # cascades the schedule away
    assert ext.get_schedule(m["schedule_id"]) is None
    assert cloud_runner.tick() == 1
    assert ext.get_schedule(g["schedule_id"])["last_status"] == "COMPLETED" and cloud_runner.tick() == 0
    monkeypatch.setenv("CLOUD_MODULE_ENABLED", "")
    assert cloud_runner.tick() == 0


def test_run_source_reports_each_failure_without_raising(monkeypatch):
    sid = _kept()
    src = ext.source_for_scan(sid)["source_id"]
    assert cloud_runner.run_source("CSRC-" + "0" * 16, "w", cloud_runner.SYSTEM_ACTOR) == ("SOURCE_MISSING", None)
    monkeypatch.setattr(cloud, "_scanner_post", lambda *a, **k: FakeResponse(200, {**CLEAN, "status": "FAILED"}))
    assert cloud_runner.run_source(src, "w", cloud_runner.SYSTEM_ACTOR)[0] == "FAILED"
    monkeypatch.setattr(cloud, "_scanner_post", lambda *a, **k: (_ for _ in ()).throw(HTTPException(502, "cloud scanner unavailable")))
    assert cloud_runner.run_source(src, "w", cloud_runner.SYSTEM_ACTOR) == ("ERROR: cloud scanner unavailable", None)
    monkeypatch.setattr(cloud, "_scanner_post", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom with details")))
    status = cloud_runner.run_source(src, "w", cloud_runner.SYSTEM_ACTOR)
    assert status == ("ERROR: RuntimeError", None) and "details" not in status[0]


def test_scanner_refusal_and_bad_json_surface_as_http_errors(monkeypatch):
    monkeypatch.setattr(cloud, "_scanner_post", lambda *a, **k: FakeResponse(500, CLEAN))
    assert client.post("/api/v1/cloud/scans", files={"file": ("a.tf", b"x")}).status_code == 502
    monkeypatch.setattr(cloud, "_scanner_post", lambda *a, **k: FakeResponse(200, None))
    assert client.post("/api/v1/cloud/scans", files={"file": ("a.tf", b"x")}).status_code == 502
    monkeypatch.setattr(cloud, "_scanner_post", lambda *a, **k: FakeResponse(200, CLEAN))
    monkeypatch.setattr(cloud.store, "save_report", lambda *a, **k: (_ for _ in ()).throw(PermissionError("x")))
    assert client.post("/api/v1/cloud/scans", files={"file": ("a.tf", b"x")}).status_code == 409


def test_scheduler_loop_survives_a_failing_tick(monkeypatch):
    calls = []

    class FakeStop:
        def __init__(self):
            self.n = 0

        def is_set(self):
            self.n += 1
            return self.n > 2

        def set(self):
            self.n = 99

        def wait(self, _):
            return None

    def tick():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("tick failed")
        return 3

    handlers = []
    monkeypatch.setattr(cloud_scheduler.threading, "Event", FakeStop)
    monkeypatch.setattr(cloud_scheduler.signal, "signal", lambda sig, fn: handlers.append(fn))
    monkeypatch.setattr(cloud_scheduler.cloud_runner, "tick", tick)
    cloud_scheduler.main()
    assert len(calls) == 2 and handlers
    handlers[0](15, None)                                # the signal handler only asks the loop to stop
