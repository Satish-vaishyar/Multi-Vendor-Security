"""Data-retention job: per-table counts, dry run, audit-log immutability, admin API + CLI."""
import json
import uuid

import psycopg
import pytest
from fastapi.testclient import TestClient

from app.core import config as cfg
from app.core import db as dbmod
from app.core import rbac, tenancy
from app.core import security as sec
from app.main import app
from app.services import retention

client = TestClient(app)
PW = "Str0ng!Passw0rd#1"


def _x(sql, params=()):
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(sql, params)
        return cur.fetchall() if cur.description else cur.rowcount


def _count(sql, params=()):
    return _x(sql, params)[0][0]


def _uid(p):
    return f"{p}-{uuid.uuid4().hex[:10]}"


@pytest.fixture()
def seeded():
    """Old + fresh rows for every purge rule; returns the identifying keys."""
    k = {"tag": uuid.uuid4().hex[:10]}
    t = k["tag"]
    _x("INSERT INTO audit_log (ts, org_id, action, detail) VALUES (now() - interval '500 days', %s, %s, '{}'), "
       "(now() - interval '1 day', %s, %s, '{}')", (cfg.DEFAULT_ORG_ID, f"old.{t}", cfg.DEFAULT_ORG_ID, f"new.{t}"))
    k["jti_old"], k["jti_new"] = _uid("jti-old"), _uid("jti-new")
    _x("INSERT INTO revoked_tokens VALUES (%s, now() - interval '1 hour'), (%s, now() + interval '1 hour')",
       (k["jti_old"], k["jti_new"]))
    k["rep_old"], k["rep_new"] = _uid("RPT-old"), _uid("RPT-new")
    _x("INSERT INTO reports (report_id, pdf, created_at) VALUES (%s, %s, now() - interval '400 days'), (%s, %s, now())",
       (k["rep_old"], b"%PDF-old", k["rep_new"], b"%PDF-new"))
    k["dl_old"], k["dl_new"] = _uid("DLV-old"), _uid("DLV-new")
    _x("INSERT INTO webhook_deliveries (delivery_id, webhook_id, event, status, created_at) VALUES "
       "(%s, 'WH-x', 'e', 'SUCCESS', now() - interval '45 days'), (%s, 'WH-x', 'e', 'SUCCESS', now())",
       (k["dl_old"], k["dl_new"]))
    k["asset"] = _uid("AST-ret")
    for i in range(32):        # 32 old snapshots for one asset: the newest 30 are always kept
        _x("INSERT INTO audit_snapshots (snapshot_id, asset_id, audit_id, created_at) "
           "VALUES (%s, %s, 'A1', now() - interval '400 days' + make_interval(mins => %s))",
           (f"SNP-{t}-{i:02d}", k["asset"], i))
    yield k
    _x("DELETE FROM reports WHERE report_id IN (%s, %s)", (k["rep_old"], k["rep_new"]))
    _x("DELETE FROM revoked_tokens WHERE jti IN (%s, %s)", (k["jti_old"], k["jti_new"]))
    _x("DELETE FROM webhook_deliveries WHERE delivery_id IN (%s, %s)", (k["dl_old"], k["dl_new"]))
    _x("DELETE FROM audit_snapshots WHERE asset_id = %s", (k["asset"],))


def test_dry_run_counts_and_changes_nothing(seeded):
    t = seeded["tag"]
    purges = _count("SELECT count(*) FROM audit_log WHERE action = 'retention.purge'")
    out = retention.run(dry_run=True)
    assert out["dry_run"] is True
    c = out["counts"]
    assert c["audit_log"] >= 1 and c["revoked_tokens"] >= 1 and c["report_pdfs"] >= 1
    assert c["webhook_deliveries"] >= 1 and c["audit_snapshots"] >= 2
    assert "config_text" in out["skipped"]                      # off by default
    assert _count("SELECT count(*) FROM audit_log WHERE action = %s", (f"old.{t}",)) == 1
    assert _count("SELECT count(*) FROM revoked_tokens WHERE jti = %s", (seeded["jti_old"],)) == 1
    assert _count("SELECT count(*) FROM reports WHERE report_id = %s AND pdf IS NOT NULL", (seeded["rep_old"],)) == 1
    assert _count("SELECT count(*) FROM audit_snapshots WHERE asset_id = %s", (seeded["asset"],)) == 32
    assert _count("SELECT count(*) FROM audit_log WHERE action = 'retention.purge'") == purges   # dry run writes no purge record


def test_run_purges_old_keeps_new_and_records_itself(seeded):
    t = seeded["tag"]
    before = _count("SELECT count(*) FROM audit_log WHERE action = 'retention.purge'")
    out = retention.run()
    c = out["counts"]
    assert c["audit_log"] >= 1 and c["revoked_tokens"] >= 1 and c["report_pdfs"] >= 1
    assert c["webhook_deliveries"] >= 1 and c["audit_snapshots"] >= 2
    assert _count("SELECT count(*) FROM audit_log WHERE action = %s", (f"old.{t}",)) == 0
    assert _count("SELECT count(*) FROM audit_log WHERE action = %s", (f"new.{t}",)) == 1
    assert _count("SELECT count(*) FROM revoked_tokens WHERE jti = %s", (seeded["jti_old"],)) == 0
    assert _count("SELECT count(*) FROM revoked_tokens WHERE jti = %s", (seeded["jti_new"],)) == 1
    # report metadata survives, only the PDF bytes go
    assert _count("SELECT count(*) FROM reports WHERE report_id = %s AND pdf IS NULL", (seeded["rep_old"],)) == 1
    assert _count("SELECT count(*) FROM reports WHERE report_id = %s AND pdf IS NOT NULL", (seeded["rep_new"],)) == 1
    assert _count("SELECT count(*) FROM webhook_deliveries WHERE delivery_id = %s", (seeded["dl_old"],)) == 0
    assert _count("SELECT count(*) FROM webhook_deliveries WHERE delivery_id = %s", (seeded["dl_new"],)) == 1
    assert _count("SELECT count(*) FROM audit_snapshots WHERE asset_id = %s", (seeded["asset"],)) == 30
    # the purge is itself in the audit trail (and carries the counts)
    assert _count("SELECT count(*) FROM audit_log WHERE action = 'retention.purge'") == before + 1
    detail = _x("SELECT detail FROM audit_log WHERE action = 'retention.purge' ORDER BY id DESC LIMIT 1")[0][0]
    assert detail["counts"]["audit_log"] == c["audit_log"] and detail["cross_tenant"] is True
    # idempotent
    assert retention.run()["counts"]["audit_snapshots"] == 0


def test_audit_log_remains_append_only_outside_retention():
    tag = _uid("append-only")
    _x("INSERT INTO audit_log (action) VALUES (%s)", (tag,))
    with pytest.raises(psycopg.errors.RaiseException):
        _x("DELETE FROM audit_log WHERE action = %s", (tag,))
    with pytest.raises(psycopg.errors.RaiseException):
        _x("UPDATE audit_log SET action = 'x' WHERE action = %s", (tag,))
    with pytest.raises(psycopg.errors.RaiseException):          # even with the flag, UPDATE stays blocked
        with dbmod.get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT set_config('app.audit_retention', 'on', true)")
            cur.execute("INSERT INTO audit_log (action) VALUES ('flagtest')")
            cur.execute("UPDATE audit_log SET action = 'x' WHERE action = 'flagtest'")


def test_disabled_rule_is_skipped(monkeypatch, seeded):
    monkeypatch.setattr(cfg, "AUDIT_LOG_RETENTION_DAYS", 0)
    out = retention.run()
    assert "audit_log" in out["skipped"] and "audit_log" not in out["counts"]
    assert _count("SELECT count(*) FROM audit_log WHERE action = %s", (f"old.{seeded['tag']}",)) == 1


def test_superseded_config_text_only_when_enabled(monkeypatch):
    a = _uid("AST-cfg")
    _x("INSERT INTO assets (asset_id, name) VALUES (%s, 'r1')", (a,))
    old, newer, lone = _uid("CFG-o"), _uid("CFG-n"), _uid("CFG-l")
    _x("INSERT INTO configurations (configuration_id, asset_id, config_text, created_at) VALUES "
       "(%s, %s, 'hostname old', now() - interval '90 days'), (%s, %s, 'hostname new', now() - interval '80 days')",
       (old, a, newer, a))
    _x("INSERT INTO configurations (configuration_id, asset_id, config_text, created_at) VALUES "
       "(%s, NULL, 'unattached', now() - interval '90 days')", (lone,))
    try:
        retention.run()                                    # default: off
        assert _count("SELECT count(*) FROM configurations WHERE configuration_id = %s AND config_text = 'hostname old'", (old,)) == 1
        monkeypatch.setattr(cfg, "CONFIG_RETENTION_DAYS", 30)
        assert retention.run(dry_run=True)["counts"]["config_text"] >= 1
        retention.run()
        assert _x("SELECT config_text FROM configurations WHERE configuration_id = %s", (old,))[0][0] == retention.CONFIG_PURGED_MARK
        assert _x("SELECT config_text FROM configurations WHERE configuration_id = %s", (newer,))[0][0] == "hostname new"   # latest kept
        assert _x("SELECT config_text FROM configurations WHERE configuration_id = %s", (lone,))[0][0] == "unattached"
    finally:
        _x("DELETE FROM configurations WHERE configuration_id IN (%s, %s, %s)", (old, newer, lone))
        _x("DELETE FROM assets WHERE asset_id = %s", (a,))


# --- admin API / CLI -------------------------------------------------------------------------------------------------

@pytest.fixture()
def _auth_on(monkeypatch):
    monkeypatch.setattr(cfg, "REQUIRE_AUTH", True)
    sec.reset_throttle()
    yield
    tenancy.set_org(None)


def _hdr(role):
    email = f"{role.lower()}-{uuid.uuid4().hex[:8]}@example.com"
    sec.create_user(email, role.title(), PW, role, org_id=cfg.DEFAULT_ORG_ID)
    r = client.post("/api/v1/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['data']['access_token']}"}


def test_admin_endpoint_rbac_and_dry_run_default(_auth_on, seeded):
    assert client.post("/api/v1/admin/retention/run").status_code == 401
    assert client.post("/api/v1/admin/retention/run", headers=_hdr(rbac.VIEWER)).status_code == 403
    admin = _hdr(rbac.ADMIN)
    r = client.post("/api/v1/admin/retention/run?dry_run=true", headers=admin)
    assert r.status_code == 200 and r.json()["data"]["dry_run"] is True
    assert _count("SELECT count(*) FROM audit_log WHERE action = %s", (f"old.{seeded['tag']}",)) == 1
    r = client.post("/api/v1/admin/retention/run?dry_run=false", headers=admin)
    assert r.status_code == 200 and r.json()["data"]["counts"]["audit_log"] >= 1
    assert _count("SELECT count(*) FROM audit_log WHERE action = %s", (f"old.{seeded['tag']}",)) == 0


def test_cli_retention(capsys, seeded):
    from app import cli
    assert cli.main(["retention", "--dry-run"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["dry_run"] is True and out["counts"]["audit_log"] >= 1
    assert cli.main(["retention"]) == 0
    assert json.loads(capsys.readouterr().out)["dry_run"] is False


def test_worker_maintenance_runs_retention(monkeypatch):
    import threading
    from app import worker
    calls = []
    monkeypatch.setattr(retention, "run", lambda dry_run=False: calls.append(dry_run) or {})
    stop = threading.Event()
    monkeypatch.setattr(worker, "process_one", lambda wid: stop.set() or False)
    worker.run_forever(stop, poll_s=0.01)
    assert calls == [False]
    assert _count("SELECT count(*) FROM worker_heartbeats WHERE last_maintenance IS NOT NULL AND last_retention IS NOT NULL") >= 1
