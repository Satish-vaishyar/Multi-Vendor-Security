"""IDs + timestamps. All records live in Supabase Postgres via app.core.persist —
no in-memory stores (DB is the only source of truth)."""
from __future__ import annotations
import time
import uuid


def nid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def now() -> float:
    return time.time()
