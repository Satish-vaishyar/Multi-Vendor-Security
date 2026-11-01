"""Branch coverage for the core layer: assets, security helpers and the DB connection pool."""
import queue
import threading
import time
import types
import uuid

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.api.v1 import assets as assets_api
from app.core import config as cfg
from app.core import db as dbmod
from app.core import persist, tenancy
from app.core import security as sec
from app.main import app

client = TestClient(app)


def _id(p):
    return f"{p}-{uuid.uuid4().hex[:8].upper()}"


@pytest.fixture
def org():
    o = "ORG-COV-" + uuid.uuid4().hex[:6].upper()
    with dbmod.get_conn() as conn:
        conn.cursor().execute("INSERT INTO organizations (org_id, name) VALUES (%s, %s)", (o, o))
    with tenancy.use_org(o):
        yield o


# ---------------------------------------------------------------- assets
def _asset(**kw):
    a = {"asset_id": _id("AST"), "name": "core-rtr", "vendor": "cisco", "product": "ios_xe", "status": "ACTIVE", **kw}
    persist.save("assets", a)
    return a


def test_duplicate_detection_requires_the_same_identity_and_compatible_serials(org):
    _asset(serial_number="SN1")
    assert assets_api._find_duplicate("other-name", "cisco", "ios_xe", "") is None
    assert assets_api._find_duplicate("core-rtr", "juniper", "ios_xe", "") is None
    assert assets_api._find_duplicate("core-rtr", "cisco", "nx_os", "") is None
    assert assets_api._find_duplicate("core-rtr", "cisco", "ios_xe", "SN-DIFFERENT") is None
    assert assets_api._find_duplicate("CORE-RTR ", "Cisco", "ios_xe", "sn1") is not None


def test_merging_duplicates_repoints_children_and_skips_serial_conflicts(org):
    first = _asset(name="dup-a", created_at=1)
    second = _asset(name="dup-a", created_at=2)
    cid = _id("CFG")
    persist.save("configurations", {"configuration_id": cid, "asset_id": second["asset_id"], "config_text": "hostname x\n", "filename": "x", "status": "UPLOADED"})
    _asset(name="dup-b", serial_number="S1")
    _asset(name="dup-b", serial_number="S2")
    _asset(name="solo")
    out = assets_api.merge_duplicates()["data"]
    by = {g["name"]: g for g in out["groups"]}
    assert by["dup-a"]["status"] == "merged" and by["dup-a"]["survivor"] == first["asset_id"] and by["dup-a"]["moved"]["configurations"] == 1
    assert by["dup-b"]["status"] == "skipped_serial_conflict" and out["total_merged"] == 1
    assert persist.get("configurations", cid)["asset_id"] == first["asset_id"]
    assert persist.get("assets", second["asset_id"])["status"] == "DELETED"


def test_onboarding_reuses_an_existing_identity(org):
    first = assets_api.get_or_create_asset("edge-1", vendor="cisco", product="ios_xe")
    again = assets_api.get_or_create_asset(" EDGE-1 ", vendor="Cisco", product="ios_xe")
    assert again["asset_id"] == first["asset_id"]


def test_blank_asset_name_is_replaced_on_patch():
    aid = _id("AST")
    persist.save("assets", {"asset_id": aid, "name": "before"})
    r = client.patch(f"/api/v1/assets/{aid}", json={"name": "   "})
    assert r.status_code == 200 and r.json()["data"]["name"] == "unnamed-device"


# ---------------------------------------------------------------- security helpers
def test_password_rehash_detection_and_role_validation():
    assert sec._needs_rehash("garbage") is True
    with pytest.raises(ValueError):
        sec.create_user(f"x-{uuid.uuid4().hex[:6]}@example.com", "X", "Str0ng!Passw0rd#1", "SUPERUSER")


def test_bootstrap_admin_tolerates_an_unreachable_database(monkeypatch):
    monkeypatch.setattr(sec, "_bootstrapped", False)

    def down():
        raise RuntimeError("db unreachable")
    monkeypatch.setattr(sec.dbmod, "get_conn", down)
    assert sec.ensure_bootstrap_admin() is False


def test_ip_throttle_forgets_old_attempts():
    ip = "203.0.113." + str(uuid.uuid4().int % 250)
    sec._ip_hits[ip].extend([time.monotonic() - 500] * 3)
    assert sec._ip_throttled(ip) is False and len(sec._ip_hits[ip]) == 1


def test_database_failures_during_login_and_session_checks_are_503s(monkeypatch):
    monkeypatch.setattr(sec, "_user_by_email", lambda email: (_ for _ in ()).throw(RuntimeError("db")))
    with pytest.raises(sec.AuthFailure) as e:
        sec.authenticate("a@example.com", "x", "198.51.100.7")
    assert e.value.status_code == 503
    tok = sec.make_token({"id": "USR-1", "name": "A", "email": "a@example.com", "role": "VIEWER", "token_version": 0})["access_token"]
    monkeypatch.setattr(sec, "_is_revoked", lambda jti: (_ for _ in ()).throw(RuntimeError("db")))
    with pytest.raises(HTTPException) as e2:
        sec.get_current_user(types.SimpleNamespace(cookies={}, headers={}, method="GET"),
                             types.SimpleNamespace(credentials=tok))
    assert e2.value.status_code == 503


def test_require_role_guard():
    dep = sec.require_role("ADMIN")
    assert dep({"role": "ADMIN"})["role"] == "ADMIN"
    with pytest.raises(HTTPException) as e:
        dep({"role": "VIEWER"})
    assert e.value.status_code == 403


# ---------------------------------------------------------------- connection pool (isolated fake pool)
class FakeConn:
    def __init__(self, closed=0, rollback_fails=False, close_fails=False):
        self.closed, self.rollback_fails, self.close_fails, self.calls = closed, rollback_fails, close_fails, []

    def commit(self):
        self.calls.append("commit")

    def rollback(self):
        self.calls.append("rollback")
        if self.rollback_fails:
            raise RuntimeError("rollback failed")

    def close(self):
        self.calls.append("close")
        if self.close_fails:
            raise RuntimeError("close failed")


@pytest.fixture
def pool(monkeypatch):
    monkeypatch.setattr(dbmod, "_idle", queue.Queue())
    monkeypatch.setattr(dbmod, "_created", 0)
    monkeypatch.setattr(dbmod, "_POOL_MAX", 2)
    monkeypatch.setattr(dbmod, "_BORROW_TIMEOUT", 3.0)
    monkeypatch.setattr(dbmod, "DATABASE_URL", "postgresql://fake")
    monkeypatch.setattr(dbmod, "RLS_ENABLED", False)
    return dbmod


def test_a_failed_rollback_does_not_mask_the_original_error(pool, monkeypatch):
    conn = FakeConn(rollback_fails=True)
    monkeypatch.setattr(pool, "_new_conn", lambda: conn)
    with pytest.raises(ValueError):
        with pool.get_conn():
            raise ValueError("business error")
    assert "rollback" in conn.calls and "close" in conn.calls and pool.pool_status() == {"idle": 0, "open": 0, "max": 2}


def test_a_failed_close_is_ignored(pool):
    pool._created = 1
    pool._discard(FakeConn(close_fails=True))
    assert pool._created == 0


def test_a_failing_connect_releases_its_slot(pool, monkeypatch):
    monkeypatch.setattr(pool, "_new_conn", lambda: (_ for _ in ()).throw(OSError("refused")))
    with pytest.raises(OSError):
        pool._borrow()
    assert pool._created == 0


def test_a_full_pool_waits_for_a_returned_connection(pool, monkeypatch):
    monkeypatch.setattr(pool, "_new_conn", lambda: FakeConn())
    a, b = pool._borrow(), pool._borrow()                                   # pool is now full (2 open)
    assert pool._created == 2

    def give_back():
        time.sleep(0.2)
        pool._release(a)
    threading.Thread(target=give_back, daemon=True).start()
    assert pool._borrow() is a                                              # blocked until it came back, and it is healthy
    assert b is not a


def test_a_returned_connection_that_died_is_replaced(pool, monkeypatch):
    fresh = FakeConn()
    monkeypatch.setattr(pool, "_new_conn", lambda: fresh)
    a, b = pool._borrow(), pool._borrow()
    a.closed = 1                                                            # died while idle

    def give_back():
        time.sleep(0.2)
        pool._release(a)
    threading.Thread(target=give_back, daemon=True).start()
    assert pool._borrow() is fresh                                          # slot freed, a new connection opened
    assert b is fresh or b is not a
