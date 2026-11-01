"""Postgres row-level security as defence in depth for tenant isolation.

Runs as a plain (non-bypass) role against the real policies. The suite as a whole can also be run in this mode with
TEST_RLS=1 (see tests/conftest.py), which is how every code path was shaken out. This module restores whatever RLS
state it found, so it is safe in both modes.
"""
import os
import queue
import uuid

import psycopg
import pytest

from app import cli
from app.core import db as dbmod
from app.core import persist, tenancy

pytestmark = pytest.mark.skipif(os.getenv("TEST_RLS") == "1", reason="the whole suite already runs under RLS in this mode")

ROLE, PW = "auditor_rls_app", "rlsapp"


def _admin_url():
    from tests.conftest import _TEST_URL
    return _TEST_URL


def _role_url():
    from urllib.parse import urlparse
    u = urlparse(_admin_url())
    return _admin_url().replace(f"{u.username}:{u.password}@", f"{ROLE}:{PW}@")


def _rls_state(cur):
    cur.execute("SELECT relforcerowsecurity FROM pg_class WHERE relname = 'assets'")
    return bool(cur.fetchone()[0])


def _flush_pool():
    while True:
        try:
            conn, _ = dbmod._idle.get_nowait()
        except queue.Empty:
            break
        conn.close()
    with dbmod._guard:
        dbmod._created = 0


@pytest.fixture
def rls(monkeypatch):
    admin = psycopg.connect(_admin_url(), autocommit=True)
    cur = admin.cursor()
    was_on = _rls_state(cur)
    cur.execute(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{ROLE}') THEN "
                f"CREATE ROLE {ROLE} LOGIN PASSWORD '{PW}' NOSUPERUSER NOBYPASSRLS; END IF; END $$")
    for o in ("ORG-RLS-A", "ORG-RLS-B"):
        cur.execute("INSERT INTO organizations (org_id, name) VALUES (%s, %s) ON CONFLICT DO NOTHING", (o, o))
    cur.execute("SELECT 1")
    admin_cli_url = dbmod.DATABASE_URL
    yield admin, cur
    _flush_pool()
    monkeypatch.undo()
    dbmod.DATABASE_URL = admin_cli_url
    if not was_on:
        cur.execute((cli.DB_DIR / "rls_disable.sql").read_text(encoding="utf-8"))
    cur.execute("DELETE FROM assets WHERE org_id IN ('ORG-RLS-A', 'ORG-RLS-B')")
    admin.close()


def _enable(cur):
    cur.execute((cli.DB_DIR / "rls_enable.sql").read_text(encoding="utf-8"))
    cur.execute(f"GRANT USAGE ON SCHEMA public TO {ROLE}")
    cur.execute(f"GRANT ALL ON ALL TABLES IN SCHEMA public TO {ROLE}")
    cur.execute(f"GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO {ROLE}")


def _asset(cur, org, name):
    aid = "AST-" + uuid.uuid4().hex[:8]
    cur.execute("INSERT INTO assets (asset_id, name, org_id) VALUES (%s, %s, %s)", (aid, name, org))
    return aid


def test_policies_isolate_tenants_for_a_plain_role(rls):
    _, cur = rls
    _enable(cur)
    a, b = _asset(cur, "ORG-RLS-A", "a-router"), _asset(cur, "ORG-RLS-B", "b-router")
    with psycopg.connect(_role_url(), autocommit=True) as app:
        c = app.cursor()
        c.execute("SELECT count(*) FROM assets")
        assert c.fetchone()[0] == 0                                           # no tenant bound -> nothing visible
        c.execute("SELECT set_config('app.org_id', 'ORG-RLS-A', false)")
        c.execute("SELECT asset_id FROM assets WHERE org_id LIKE 'ORG-RLS-%'")
        assert [r[0] for r in c.fetchall()] == [a]
        c.execute("SELECT count(*) FROM assets WHERE asset_id = %s", (b,))
        assert c.fetchone()[0] == 0                                           # a forgotten WHERE still cannot see B
        c.execute("UPDATE assets SET name = 'hijack' WHERE asset_id = %s", (b,))
        assert c.rowcount == 0                                                # ...nor change it
        c.execute("DELETE FROM assets WHERE asset_id = %s", (b,))
        assert c.rowcount == 0
        with pytest.raises(psycopg.errors.InsufficientPrivilege):             # ...nor write a row into B's tenant
            c.execute("INSERT INTO assets (asset_id, name, org_id) VALUES ('AST-x', 'x', 'ORG-RLS-B')")
        c.execute("SELECT set_config('app.org_id', '*', false)")
        c.execute("SELECT count(*) FROM assets WHERE org_id LIKE 'ORG-RLS-%'")
        assert c.fetchone()[0] == 2                                           # explicit system scope sees everything
    cur.execute("SELECT name FROM assets WHERE asset_id = %s", (b,))
    assert cur.fetchone()[0] == "b-router"


def test_audit_log_and_organizations_are_not_row_filtered(rls):
    _, cur = rls
    _enable(cur)
    cur.execute("SELECT relrowsecurity FROM pg_class WHERE relname IN ('audit_log', 'organizations')")
    assert [r[0] for r in cur.fetchall()] == [False, False]
    cur.execute("SELECT count(*) FROM pg_class WHERE relrowsecurity AND relname IN ('assets', 'users', 'jobs', 'audits', 'findings')")
    assert cur.fetchone()[0] == 5


def test_application_binds_the_tenant_per_connection_checkout(rls, monkeypatch):
    _, cur = rls
    _enable(cur)
    _flush_pool()
    monkeypatch.setattr(dbmod, "DATABASE_URL", _role_url())
    monkeypatch.setattr(dbmod, "RLS_ENABLED", True)
    rec = {"asset_id": "AST-" + uuid.uuid4().hex[:8], "name": "via-app", "org_id": "ORG-RLS-A"}
    with tenancy.use_org("ORG-RLS-A"):
        persist.save("assets", dict(rec))
        assert persist.get("assets", rec["asset_id"]) is not None
    with tenancy.use_org("ORG-RLS-B"):
        assert persist.get("assets", rec["asset_id"]) is None                 # same pooled connection, re-bound to B
    with tenancy.unscoped():
        assert persist.get("assets", rec["asset_id"]) is not None             # system scope
    with tenancy.use_org("ORG-RLS-B"):                                        # raw SQL with a forgotten filter
        with dbmod.get_conn() as conn:
            c = conn.cursor()
            c.execute("SELECT count(*) FROM assets WHERE name = 'via-app'")
            assert c.fetchone()[0] == 0


def test_rebinding_is_skipped_when_the_tenant_is_unchanged(rls, monkeypatch):
    _, cur = rls
    _enable(cur)
    _flush_pool()
    monkeypatch.setattr(dbmod, "DATABASE_URL", _role_url())
    monkeypatch.setattr(dbmod, "RLS_ENABLED", True)
    seen = []
    real = psycopg.Cursor.execute

    def spy(self, query, *a, **k):
        if "set_config" in str(query):
            seen.append(a[0] if a else None)
        return real(self, query, *a, **k)
    monkeypatch.setattr(psycopg.Cursor, "execute", spy)
    with tenancy.use_org("ORG-RLS-A"):
        for _ in range(3):
            with dbmod.get_conn():
                pass
    assert len(seen) == 1


def test_cli_status_enable_disable(rls, capsys):
    _, cur = rls
    assert cli.main(["rls-enable"]) == 0
    out = capsys.readouterr().out
    assert "tables_with_rls=" in out and "role_bypasses_rls=True" in out and "do not protect it" in out
    assert cli.main(["rls-status"]) == 0 and "tables_forced=" in capsys.readouterr().out
    assert cli.main(["rls-disable"]) == 0
    assert "tables_with_rls=0" in capsys.readouterr().out
    cur.execute("SELECT count(*) FROM pg_policies WHERE policyname = 'tenant_isolation'")
    assert cur.fetchone()[0] == 0
