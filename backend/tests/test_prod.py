"""Production wiring tests: /readyz, validation envelope, bulk-upload cap,
env-gated auth, and the Supabase db helper (all with fakes — no network)."""
import os
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core import config as cfg
from app.core import db as dbmod
from app.core import security as sec

client = TestClient(app)
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")


def _token():
    r = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200
    return r.json()["data"]["access_token"]


def test_readyz_skipped_when_no_db(monkeypatch):
    monkeypatch.setattr(cfg, "DATABASE_URL", "")
    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.json()["db"] == {"configured": False, "status": "skipped"}
    assert "X-Request-ID" in r.headers


def test_readyz_up(monkeypatch):
    monkeypatch.setattr(cfg, "DATABASE_URL", "postgresql://x")
    monkeypatch.setattr(dbmod, "ping", lambda: {"public_tables": 10})
    import app.main as mainmod
    monkeypatch.setattr(mainmod.cfg, "DATABASE_URL", "postgresql://x", raising=False)
    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.json()["db"]["status"] == "up"


def test_readyz_down(monkeypatch):
    def boom():
        raise TimeoutError("no route")
    monkeypatch.setattr(dbmod, "ping", boom)
    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.json()["db"]["status"] == "down"


def test_validation_envelope():
    r = client.post("/api/v1/assets", json={"name": ""})
    assert r.status_code == 422
    body = r.json()
    assert body["success"] is False and body["error"]["code"] == "VALIDATION_ERROR"


def test_bulk_upload_cap(monkeypatch):
    monkeypatch.setattr(cfg, "MAX_BULK_FILES", 1)
    r = client.post("/api/v1/configurations/bulk-upload",
                    files=[("files", ("a.txt", b"hostname R1\n", "text/plain")),
                           ("files", ("b.txt", b"hostname R2\n", "text/plain"))],
                    data={"asset_id": "AST-001"})
    assert r.status_code == 400


def test_require_auth_enforced(monkeypatch):
    monkeypatch.setattr(cfg, "REQUIRE_AUTH", True)
    assert client.get("/api/v1/dashboard/summary").status_code == 401
    h = {"Authorization": f"Bearer {_token()}"}
    assert client.get("/api/v1/dashboard/summary", headers=h).status_code == 200
    # dev default still passes through without a token
    monkeypatch.setattr(cfg, "REQUIRE_AUTH", False)
    assert client.get("/api/v1/dashboard/summary").status_code == 200
    assert sec.require_user.__doc__ is not None


class _FakeCursor:
    def __init__(self, rows):
        self._rows = list(rows)
    def execute(self, *a, **k):
        pass
    def fetchone(self):
        return self._rows.pop(0)


class _FakeConn:
    def __init__(self, monkeypatch, rows, fail=False):
        self.calls = []
        self._rows = rows
        self._fail = fail
    def cursor(self):
        return _FakeCursor(self._rows)
    def commit(self):
        self.calls.append("commit")
    def rollback(self):
        self.calls.append("rollback")
    def close(self):
        self.calls.append("close")


def test_db_helper_commit(monkeypatch):
    import psycopg
    fake = _FakeConn(monkeypatch, [])
    monkeypatch.setattr(psycopg, "connect", lambda *a, **k: fake)
    monkeypatch.setattr(dbmod, "DATABASE_URL", "postgresql://x")
    assert dbmod.is_configured() is True
    with dbmod.get_conn() as conn:
        assert conn is fake
    assert fake.calls == ["commit", "close"]


def test_db_helper_rollback(monkeypatch):
    import psycopg
    fake = _FakeConn(monkeypatch, [])
    monkeypatch.setattr(psycopg, "connect", lambda *a, **k: fake)
    monkeypatch.setattr(dbmod, "DATABASE_URL", "postgresql://x")
    with pytest.raises(ValueError):
        with dbmod.get_conn():
            raise ValueError("boom")
    assert fake.calls == ["rollback", "close"]


def test_db_helper_no_url(monkeypatch):
    monkeypatch.setattr(dbmod, "DATABASE_URL", "")
    assert dbmod.is_configured() is False
    with pytest.raises(RuntimeError):
        with dbmod.get_conn():
            pass


def test_db_ping(monkeypatch):
    import psycopg
    rows = [("PostgreSQL 17", "postgres", "postgres"), (10,)]
    fake = _FakeConn(monkeypatch, rows)
    monkeypatch.setattr(psycopg, "connect", lambda *a, **k: fake)
    monkeypatch.setattr(dbmod, "DATABASE_URL", "postgresql://x")
    out = dbmod.ping()
    assert out == {"version": "PostgreSQL 17", "database": "postgres",
                   "user": "postgres", "public_tables": 10}


def test_db_load_env_failure(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("no dotenv")
    real = dbmod.load_dotenv
    monkeypatch.setattr(dbmod, "load_dotenv", boom)
    try:
        dbmod._load_env()
    finally:
        monkeypatch.setattr(dbmod, "load_dotenv", real)


def test_dashboard_frameworks_with_malformed_entry():
    from app.core import persist
    aid = client.post("/api/v1/assets", json={"name": "BadFw-Asset"}).json()["data"]["asset_id"]
    cid = client.post("/api/v1/configurations/upload",
                      files={"file": ("r.txt", b"hostname R1\n", "text/plain")},
                      data={"asset_id": aid}).json()["data"]["configuration_id"]
    persist.save("audits", {"audit_id": "AUD-BADFW", "asset_id": aid,
                            "configuration_id": cid, "status": "COMPLETED",
                            "summary": {"compliance_score": 50.0},
                            "by_framework": {"CIS": {"compliance_score": "nan-x"},
                                             "NIST": None}})
    try:
        r = client.get("/api/v1/dashboard/summary")
        assert r.status_code == 200
        # malformed CIS string is skipped, never poisons the averages
        for fw, v in r.json()["data"]["frameworks"].items():
            assert isinstance(v["score"], (int, float)), fw
    finally:
        persist.delete("audits", "AUD-BADFW")


def test_audit_rejects_unknown_asset():
    aid = client.post("/api/v1/assets", json={"name": "Reject-Asset"}).json()["data"]["asset_id"]
    cid = client.post("/api/v1/configurations/upload",
                      files={"file": ("r.txt", b"hostname R1\n", "text/plain")},
                      data={"asset_id": aid}).json()["data"]["configuration_id"]
    r = client.post("/api/v1/audits", json={"asset_id": "AST-DOES-NOT-EXIST",
                                            "configuration_id": cid})
    assert r.status_code == 404


def test_assets_list_without_filters():
    assert client.get("/api/v1/assets").status_code == 200


def test_persist_delete_roundtrip():
    from app.core import persist
    persist.save("assets", {"asset_id": "AST-TMPDEL", "name": "tmp"})
    assert persist.delete("assets", "AST-TMPDEL") is True
    assert persist.delete("assets", "AST-TMPDEL") is False
    assert persist.update("assets", "AST-TMPDEL", {"status": "X"}) is None
