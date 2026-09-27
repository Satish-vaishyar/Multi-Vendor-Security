"""DB-only persistence for every API record (Supabase Postgres).

All routes read/write through here — no in-memory dicts. Each table keeps
typed key/filter columns; the full record dict lives in `data` JSONB.
Two large/relational payloads are stored natively instead:
  - audits.findings  -> findings table rows (re-attached on read)
  - reports.pdf      -> reports.pdf BYTEA column (bytes are not JSON)
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

from app.core import db as dbmod

# entity -> table, pk column, scalar key columns, jsonb columns
_SCHEMA: Dict[str, Dict[str, Any]] = {
    "users": {"table": "users", "pk": "id",
              "keys": ["email", "name", "password_hash", "role"], "json": []},
    "assets": {"table": "assets", "pk": "asset_id",
               "keys": ["name", "vendor", "product", "model", "version", "serial_number",
                        "ip_address", "environment", "criticality", "status"], "json": []},
    "configurations": {"table": "configurations", "pk": "configuration_id",
                       "keys": ["asset_id", "filename", "size", "lines", "sha256",
                                "config_text", "detected_vendor", "detected_platform",
                                "detected_version", "status"], "json": ["detection"]},
    "audits": {"table": "audits", "pk": "audit_id",
               "keys": ["asset_id", "configuration_id", "status", "progress",
                        "config_sha256", "duration_s"],
               "json": ["vendor", "stages", "versions", "summary", "by_framework",
                        "compliance", "cve", "pqc", "security", "canonical_ir"]},
    "findings": {"table": "findings", "pk": "finding_id",
                 "keys": ["audit_id", "asset_id", "engine", "type", "title",
                          "severity", "status", "control_id", "confidence"],
                 "json": ["evidence", "risk", "remediation"]},
    "training": {"table": "training_queue", "pk": "training_id",
                 "keys": ["vendor", "platform", "raw_command", "status"],
                 "json": ["context", "suggestion"]},
    "mappings": {"table": "mapping_registry", "pk": "id",
                 "keys": ["vendor", "platform", "source_token", "canonical_property",
                          "confidence", "status", "approved_by", "mapping_version"],
                 "json": ["canonical_value"]},
    "remediations": {"table": "remediations", "pk": "id",
                     "keys": ["finding_id", "status", "approved_by"], "json": ["steps"]},
    "reports": {"table": "reports", "pk": "report_id",
                "keys": ["audit_id", "format", "status", "download_path"], "json": []},
    "jobs": {"table": "jobs", "pk": "job_id",
             "keys": ["kind", "status"], "json": ["payload", "result"]},
}

# record keys kept out of `data` (stored natively elsewhere)
_NATIVE: Dict[str, Any] = {"audits": {"findings"}, "reports": {"pdf"}}


def _adapt(entity: str, col: str, value: Any) -> Any:
    from psycopg.types.json import Jsonb
    if value is None:
        return None
    if col in (_SCHEMA[entity]["json"] or []):
        return Jsonb(value)
    if col == "frameworks":
        return list(value or [])
    return value


def _qi(col: str) -> str:
    return '"format"' if col == "format" else col


def save(entity: str, record: Dict[str, Any]) -> Dict[str, Any]:
    """Upsert a full record dict. Returns the record.

    Key columns with value None are omitted so DB defaults apply instead of
    violating NOT NULL constraints; `data` always carries the full record.
    """
    from psycopg.types.json import Jsonb
    s = _SCHEMA[entity]
    pk, table = s["pk"], s["table"]
    cand = [pk] + s["keys"] + [c for c in s["json"]] + (
        ["frameworks"] if entity == "audits" else []) + (
        ["pdf"] if entity == "reports" else [])
    raw: Dict[str, Any] = {pk: record.get(pk)}
    for c in s["keys"]:
        raw[c] = record.get(c)
    for c in s["json"]:
        raw[c] = _adapt(entity, c, record.get(c))
    if entity == "audits":
        raw["frameworks"] = _adapt(entity, "frameworks", record.get("frameworks"))
    if entity == "reports":
        raw["pdf"] = record.get("pdf")
    cols = [c for c in cand if raw.get(c) is not None] + ["data"]
    raw["data"] = Jsonb({k: v for k, v in record.items() if k not in _NATIVE.get(entity, set())})
    assigns = ", ".join(f"{_qi(c)}=EXCLUDED.{_qi(c)}" for c in cols[1:])
    placeholders = ", ".join(["%s"] * len(cols))
    names = ", ".join(_qi(c) for c in cols)
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"INSERT INTO {table} ({names}) VALUES ({placeholders}) "
                    f"ON CONFLICT ({pk}) DO UPDATE SET {assigns}",
                    [raw[c] for c in cols])
    return record


def get(entity: str, pk_value: str, inflate: bool = True) -> Optional[Dict[str, Any]]:
    s = _SCHEMA[entity]
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT data FROM {s['table']} WHERE {s['pk']}=%s", (pk_value,))
        r = cur.fetchone()
    if not r:
        return None
    if not inflate:
        return dict(r[0] or {})
    return _inflate(entity, r[0], pk_value)


def count_by(entity: str, cols: Any, **filters: Any) -> List[Dict[str, Any]]:
    """GROUP BY counts without fetching rows.

    cols: a column name or list of column names. Returns e.g.
    [{"engine": "cve", "severity": "HIGH", "n": 3}, ...].
    """
    s = _SCHEMA[entity]
    cols = [cols] if isinstance(cols, str) else list(cols)
    clauses = [f"UPPER({k}::text)=UPPER(%s)" for k in filters]
    vals = list(filters.values())
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    group = ", ".join(cols)
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT {group}, COUNT(*) FROM {s['table']} {where} GROUP BY {group}", vals)
        rows = cur.fetchall()
    return [dict(zip(cols + ["n"], r)) for r in rows]


def count(entity: str, **filters: Any) -> int:
    """SELECT COUNT(*) with key-column equality filters (no row transfer)."""
    s = _SCHEMA[entity]
    clauses = [f"UPPER({k}::text)=UPPER(%s)" for k in filters]
    vals = list(filters.values())
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT COUNT(*) FROM {s['table']} {where}", vals)
        r = cur.fetchone()
    return int(r[0]) if r else 0


def _select_key(col: str) -> str:
    """Dict key for a projected column; supports 'expr AS alias' projections."""
    low = col.lower()
    if " as " in low:
        return col[low.index(" as ") + 4:].strip().strip('"')
    return col.split(".")[-1].strip('"')


def select(entity: str, columns: List[str], order: str = "created_at DESC",
           limit: int = 50, **filters: Any) -> List[Dict[str, Any]]:
    """Projected list read — only the given columns, no heavy inflate.

    Plain JSONB columns come back parsed. Items may also be raw SQL
    projections with aliases (e.g. "data->'flat_ir' AS flat_ir") — callers
    pass code constants only, never user input.
    """
    s = _SCHEMA[entity]
    cols = ", ".join(columns)
    keys = [_select_key(c) for c in columns]
    clauses = [f"UPPER({k}::text)=UPPER(%s)" for k in filters]
    vals = list(filters.values())
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT {cols} FROM {s['table']} {where} ORDER BY {order} LIMIT {int(limit)}", vals)
        rows = cur.fetchall()
    return [dict(zip(keys, r)) for r in rows]


def find(entity: str, order: str = "ASC", **filters: Any) -> List[Dict[str, Any]]:
    """List records; filters are key-column equalities (case-insensitive for text)."""
    s = _SCHEMA[entity]
    clauses = [f"UPPER({k}::text)=UPPER(%s)" for k in filters]
    vals = list(filters.values())
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT data FROM {s['table']} {where} ORDER BY created_at {order}", vals)
        rows = cur.fetchall()
    return [d for (d,) in rows]


def update(entity: str, pk_value: str, patch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rec = get(entity, pk_value)
    if rec is None:
        return None
    rec.update(patch)
    return save(entity, rec)


def delete(entity: str, pk_value: str) -> bool:
    s = _SCHEMA[entity]
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"DELETE FROM {s['table']} WHERE {s['pk']}=%s", (pk_value,))
        return cur.rowcount > 0


def clear(entity: str) -> int:
    s = _SCHEMA[entity]
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"DELETE FROM {s['table']}")
        return cur.rowcount


def _inflate(entity: str, data: Any, pk_value: str) -> Dict[str, Any]:
    rec = dict(data or {})
    if entity == "audits":
        rec["findings"] = find("findings", audit_id=rec.get("audit_id", pk_value))
    if entity == "reports":
        with dbmod.get_conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT pdf FROM reports WHERE report_id=%s", (pk_value,))
            r = cur.fetchone()
        rec["pdf"] = bytes(r[0]) if r and r[0] is not None else b""
    return rec
