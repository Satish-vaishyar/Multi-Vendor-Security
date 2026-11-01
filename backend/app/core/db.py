"""Supabase/Postgres connection helper (cloud DB).

Reads DATABASE_URL from backend/.env (see .env.example). Falls back to the
existing in-memory store in app.core.store when unset, so local dev keeps
working without a DB.
"""
from __future__ import annotations
import os
import queue
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None  # type: ignore


def _load_env() -> None:
    if load_dotenv is None:  # pragma: no cover - defensive
        return
    try:
        load_dotenv(Path(__file__).parent.parent.parent / ".env")
    except Exception:
        pass


_load_env()

DATABASE_URL = os.getenv("DATABASE_URL", "")
# Row-level security binding: when on, every checked-out connection carries the caller's tenant in `app.org_id`
# (see app/db/rls_enable.sql). Off by default; turn on only after `python -m app.cli rls-enable` and connecting as a
# role that does not bypass RLS.
RLS_ENABLED = os.getenv("RLS_ENABLED", "false").lower() in ("1", "true", "yes")


def is_configured() -> bool:
    return bool(DATABASE_URL)


@contextmanager
def get_conn() -> Iterator[object]:
    """Yield a pooled psycopg3 connection to Supabase. Requires psycopg[binary].

    Connections are reused across requests (each request previously paid a
    full TLS + auth handshake, ~6s). Checkouts are exclusive per thread.
    """
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set — add it to backend/.env")
    conn = _borrow()
    try:
        if RLS_ENABLED:
            _bind_org(conn)
        yield conn
        conn.commit()  # type: ignore[attr-defined]
        _release(conn)
    except Exception:
        try:
            conn.rollback()  # type: ignore[attr-defined]
        except Exception:
            pass
        _discard(conn)
        raise


def _bind_org(conn) -> None:  # type: ignore[no-untyped-def]
    """Tell Postgres which tenant this checkout acts for ('*' = explicit system scope). One round trip, and only when
    the pooled connection last served a different tenant."""
    from app.core import tenancy      # lazy: tenancy -> config, never back to db
    org = "*" if tenancy.is_unscoped() else tenancy.current_org()
    if getattr(conn, "_rls_org", None) != org:
        conn.cursor().execute("SELECT set_config('app.org_id', %s, false)", (org,))
        try:
            conn._rls_org = org
        except Exception:     # pragma: no cover - a connection type that forbids attributes just rebinds every time
            pass


# --- process-wide pool (stdlib only; no extra dependency) --------------------

_POOL_MAX = int(os.getenv("DB_POOL_SIZE", "10"))
_BORROW_TIMEOUT = float(os.getenv("DB_POOL_TIMEOUT", "30"))
_IDLE_TTL = 300.0  # re-validate connections idle longer than this

_idle: "queue.Queue[tuple]" = queue.Queue()
_created = 0
_guard = threading.Lock()


def _new_conn():  # type: ignore[no-untyped-def]
    import psycopg

    # sslmode=require is already in the URL query string for Supabase.
    return psycopg.connect(DATABASE_URL, connect_timeout=15)


def _healthy(conn) -> bool:  # type: ignore[no-untyped-def]
    try:
        return conn.closed == 0
    except Exception:
        return False


def _borrow():  # type: ignore[no-untyped-def]
    """Take an idle connection, open a fresh one, or wait for one to return."""
    global _created
    while True:
        try:
            conn, _ = _idle.get_nowait()
        except queue.Empty:
            break
        if _healthy(conn):
            return conn
        with _guard:
            _created -= 1
    with _guard:
        if _created < _POOL_MAX:
            _created += 1
            fresh = True
        else:
            fresh = False
    if fresh:
        try:
            return _new_conn()
        except Exception:
            with _guard:
                _created -= 1
            raise
    conn, _ = _idle.get(timeout=_BORROW_TIMEOUT)
    if _healthy(conn):
        return conn
    with _guard:
        _created -= 1
    return _borrow()


def _release(conn) -> None:  # type: ignore[no-untyped-def]
    _idle.put((conn, time.monotonic()))


def _discard(conn) -> None:  # type: ignore[no-untyped-def]
    global _created
    try:
        conn.close()
    except Exception:
        pass
    with _guard:
        _created -= 1


def pool_status() -> dict:
    """Observability for the pool (idle count, open count)."""
    return {"idle": _idle.qsize(), "open": _created, "max": _POOL_MAX}


def ping() -> dict:
    """Lightweight connectivity check, used for /health/db style probes."""
    with get_conn() as conn:  # type: ignore[arg-type]
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("select version(), current_database(), current_user;")
        ver, db, user = cur.fetchone()
        cur.execute("select count(*) from information_schema.tables where table_schema='public';")
        (tables,) = cur.fetchone()
        # The application needs the tenancy/auth migration (org_id columns, audit_log, ...).
        cur.execute("select to_regclass('public.organizations') is not null and exists ("
                    "select 1 from information_schema.columns where table_name='users' and column_name='org_id')")
        (schema_current,) = cur.fetchone()
    return {"version": ver, "database": db, "user": user, "public_tables": tables,
            "schema_current": bool(schema_current)}
