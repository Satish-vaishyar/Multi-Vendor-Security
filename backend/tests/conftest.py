"""Test harness: tests ALWAYS run against a disposable local Postgres.

The suite must never touch the production/Supabase database configured in
backend/.env. Environment is pinned BEFORE `app` is imported (dotenv does not
override variables that are already set), then the schema is (re)created.

Start the database once:
    docker run -d --name auditor-test-pg -e POSTGRES_PASSWORD=postgres \
        -e POSTGRES_DB=auditor_test -p 55432:5432 pgvector/pgvector:pg16
Override with TEST_DATABASE_URL (host must be localhost / 127.0.0.1 / db-test).
"""
import os
import pathlib
from urllib.parse import urlparse

_TEST_URL = os.getenv("TEST_DATABASE_URL",
                      "postgresql://postgres:postgres@localhost:55432/auditor_test")
_host = (urlparse(_TEST_URL).hostname or "").lower()
if _host not in ("localhost", "127.0.0.1", "db-test"):
    raise RuntimeError(f"Refusing to run tests against non-local database host {_host!r}")

os.environ["DATABASE_URL"] = _TEST_URL
os.environ["ENV"] = "development"
os.environ["REQUIRE_AUTH"] = "false"
os.environ["ADMIN_EMAIL"] = "admin@example.com"
os.environ["ADMIN_PASSWORD"] = "admin123"
os.environ["FEATHERLESS_API_KEY"] = ""
os.environ["ALLOW_EXTERNAL_LLM"] = "false"
os.environ["WEBHOOK_ALLOW_PRIVATE"] = "true"   # tests post to a loopback receiver (dev only; production never allows loopback)
os.environ["EMBEDDED_WORKER"] = "false"   # tests drive the worker explicitly
os.environ["PASSWORD_HASH_ITERATIONS"] = "1000"  # fast hashing in tests only
os.environ["ARTIFACT_VERIFY"] = "strict"
os.environ["RATE_LIMIT_EXPENSIVE_PER_MIN"] = "0"   # the expensive-endpoint limiter is exercised explicitly in tests/test_pentest.py

import psycopg  # noqa: E402

_DB_DIR = pathlib.Path(__file__).resolve().parent.parent / "app" / "db"


def _bootstrap() -> None:
    with psycopg.connect(_TEST_URL, autocommit=True, connect_timeout=10) as conn:
        cur = conn.cursor()
        cur.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        order = ["schema.sql"] + sorted(p.name for p in _DB_DIR.glob("migrate_*.sql"))
        for name in order:
            cur.execute((_DB_DIR / name).read_text(encoding="utf-8"))


def _rls_mode() -> None:
    """TEST_RLS=1: run the whole suite as a plain (non-bypass) role with row-level security enforced, to prove no code
    path depends on seeing other tenants' rows or forgets to bind its tenant."""
    with psycopg.connect(_TEST_URL, autocommit=True, connect_timeout=10) as conn:
        cur = conn.cursor()
        cur.execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auditor_rls_app') THEN "
                    "CREATE ROLE auditor_rls_app LOGIN PASSWORD 'rlsapp' NOSUPERUSER NOBYPASSRLS; END IF; END $$")
        cur.execute((_DB_DIR / "rls_enable.sql").read_text(encoding="utf-8"))
        cur.execute("GRANT USAGE ON SCHEMA public TO auditor_rls_app")
        cur.execute("GRANT ALL ON ALL TABLES IN SCHEMA public TO auditor_rls_app")
        cur.execute("GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO auditor_rls_app")
    u = urlparse(_TEST_URL)
    os.environ["DATABASE_URL"] = _TEST_URL.replace(f"{u.username}:{u.password}@", "auditor_rls_app:rlsapp@")
    os.environ["RLS_ENABLED"] = "true"


try:
    _bootstrap()
    if os.getenv("TEST_RLS") == "1":
        _rls_mode()
except Exception as exc:  # pragma: no cover - environment guard
    raise RuntimeError(
        "Test database unavailable. Start it with:\n"
        "  docker run -d --name auditor-test-pg -e POSTGRES_PASSWORD=postgres "
        "-e POSTGRES_DB=auditor_test -p 55432:5432 pgvector/pgvector:pg16\n"
        f"({exc})") from exc


import pytest  # noqa: E402


def system_scope(conn):
    """For tests that open their own psycopg connection: under TEST_RLS=1 bind the system scope so raw SQL sees every tenant."""
    if os.getenv("RLS_ENABLED") == "true":
        conn.execute("SELECT set_config('app.org_id', '*', false)")
    return conn


@pytest.fixture(autouse=True)
def _cov_test_isolation(request):
    """The branch-coverage tests (test_cov_*) enqueue jobs and create webhooks to exercise error paths; none of that may leak
    into later tests (a leftover queued job would be run by the next test that drains the queue)."""
    import time
    if not request.module.__name__.rsplit(".", 1)[-1].startswith("test_cov_"):
        yield
        return
    t0 = time.time() - 1
    yield
    with psycopg.connect(os.environ["DATABASE_URL"], autocommit=True) as c:
        system_scope(c)
        c.execute("DELETE FROM jobs WHERE status IN ('QUEUED', 'RUNNING') AND created_at >= to_timestamp(%s)", (t0,))
        c.execute("DELETE FROM webhooks WHERE name LIKE 'cov-%%'")


@pytest.fixture(autouse=True)
def _reset_login_throttle():
    """Per-IP login throttling is process-wide state; isolate tests from each other."""
    from app.core import security
    security.reset_throttle()
    yield


@pytest.fixture(autouse=True)
def _no_network_kev(monkeypatch):
    """The sync endpoint also pulls the CISA KEV feed; tests must never hit the network or rewrite the real KB."""
    try:
        import src.cve.kev as kev
    except Exception:       # okf not importable yet (collection phase)
        return
    monkeypatch.setattr(kev, "sync_kev", lambda *a, **k: {"ok": False, "error": "disabled in tests"})
