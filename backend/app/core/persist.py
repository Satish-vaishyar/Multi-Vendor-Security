"""DB-only persistence for every API record (Supabase Postgres).

All routes read/write through here — no in-memory dicts. Each table keeps
typed key/filter columns; the full record dict lives in `data` JSONB.
Two large/relational payloads are stored natively instead:
  - audits.findings  -> findings table rows (re-attached on read)
  - reports.pdf      -> reports.pdf BYTEA column (bytes are not JSON)
"""
from __future__ import annotations
import re
from typing import Any, Dict, List, Optional, Tuple

from app.core import crypto
from app.core import db as dbmod
from app.core import tenancy

# entity -> table, pk column, scalar key columns, jsonb columns
_SCHEMA: Dict[str, Dict[str, Any]] = {
    "users": {"table": "users", "pk": "id",
              "keys": ["email", "name", "password_hash", "role", "failed_attempts", "locked_until",
                       "token_version", "must_change_password", "disabled"], "json": []},
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

# Fields encrypted at rest (column AND the copy inside `data`). Transparent to callers.
_ENCRYPTED: Dict[str, List[str]] = {
    "configurations": ["config_text"],
    "training": ["raw_command"],
}

_ORDER_RE = re.compile(r"^[a-z_]+(\s+(ASC|DESC))?$", re.IGNORECASE)
_COL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PROJ_RE = re.compile(r"^data(->>?'[A-Za-z0-9_]+')+\s+AS\s+[A-Za-z_][A-Za-z0-9_]*$", re.IGNORECASE)


def _known_cols(entity: str) -> set:
    s = _SCHEMA[entity]
    return {s["pk"], "org_id", "created_at"} | set(s["keys"]) | set(s["json"])


def _check_filters(entity: str, filters: Dict[str, Any]) -> None:
    bad = [k for k in filters if k not in _known_cols(entity)]
    if bad:
        raise ValueError(f"unknown filter column(s) for {entity}: {bad}")


def _check_columns(columns: List[str]) -> None:
    for c in columns:
        if not (_COL_RE.match(c) or _PROJ_RE.match(c)):
            raise ValueError(f"illegal projection: {c!r}")


def _org_clause(alias: str = "") -> Tuple[List[str], List[Any]]:
    """Tenant predicate (empty when explicitly unscoped)."""
    if tenancy.is_unscoped():
        return [], []
    return [f"{alias}org_id=%s"], [tenancy.current_org()]


def _encrypt_record(entity: str, record: Dict[str, Any]) -> Dict[str, Any]:
    fields = _ENCRYPTED.get(entity)
    if not fields:
        return record
    out = dict(record)
    for f in fields:
        if out.get(f) is not None:
            out[f] = crypto.encrypt(out[f])
    return out


def _decrypt_record(entity: str, record: Dict[str, Any]) -> Dict[str, Any]:
    fields = _ENCRYPTED.get(entity)
    if not fields or record is None:
        return record
    for f in fields:
        if record.get(f) is not None:
            record[f] = crypto.decrypt(record[f])
    return record


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
    """Upsert a full record dict. Returns the (plaintext) record.

    Key columns with value None are omitted so DB defaults apply instead of
    violating NOT NULL constraints; `data` always carries the full record.
    The row is stamped with the caller's org; an upsert can never overwrite a
    row owned by a different org (raises PermissionError).
    """
    from psycopg.types.json import Jsonb
    s = _SCHEMA[entity]
    pk, table = s["pk"], s["table"]
    org = record.get("org_id") if tenancy.is_unscoped() and record.get("org_id") else tenancy.current_org()
    record["org_id"] = org
    stored = _encrypt_record(entity, record)
    cand = [pk, "org_id"] + s["keys"] + [c for c in s["json"]] + (
        ["frameworks"] if entity == "audits" else []) + (
        ["pdf"] if entity == "reports" else [])
    raw: Dict[str, Any] = {pk: stored.get(pk), "org_id": org}
    for c in s["keys"]:
        raw[c] = stored.get(c)
    for c in s["json"]:
        raw[c] = _adapt(entity, c, stored.get(c))
    if entity == "audits":
        raw["frameworks"] = _adapt(entity, "frameworks", stored.get("frameworks"))
    if entity == "reports":
        raw["pdf"] = stored.get("pdf")
    cols = [c for c in cand if raw.get(c) is not None] + ["data"]
    raw["data"] = Jsonb({k: v for k, v in stored.items() if k not in _NATIVE.get(entity, set())})
    assigns = ", ".join(f"{_qi(c)}=EXCLUDED.{_qi(c)}" for c in cols if c not in (pk, "org_id"))
    placeholders = ", ".join(["%s"] * len(cols))
    names = ", ".join(_qi(c) for c in cols)
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"INSERT INTO {table} ({names}) VALUES ({placeholders}) "
                    f"ON CONFLICT ({pk}) DO UPDATE SET {assigns} "
                    f"WHERE {table}.org_id = EXCLUDED.org_id",
                    [raw[c] for c in cols])
        if cur.rowcount == 0:
            raise PermissionError(f"{entity} {record.get(pk)!r} belongs to another organization")
    return record


def get(entity: str, pk_value: str, inflate: bool = True) -> Optional[Dict[str, Any]]:
    s = _SCHEMA[entity]
    oc, ov = _org_clause()
    where = " AND ".join([f"{s['pk']}=%s"] + oc)
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT data FROM {s['table']} WHERE {where}", [pk_value] + ov)
        r = cur.fetchone()
    if not r:
        return None
    if not inflate:
        return _decrypt_record(entity, dict(r[0] or {}))
    return _inflate(entity, r[0], pk_value)


def _where(entity: str, filters: Dict[str, Any], alias: str = "") -> Tuple[str, List[Any]]:
    _check_filters(entity, filters)
    clauses = [f"UPPER({alias}{k}::text)=UPPER(%s)" for k in filters]
    vals = list(filters.values())
    oc, ov = _org_clause(alias)
    clauses += oc
    vals += ov
    return (f"WHERE {' AND '.join(clauses)}" if clauses else ""), vals


def count_by(entity: str, cols: Any, _in: Optional[Dict[str, List[Any]]] = None,
             **filters: Any) -> List[Dict[str, Any]]:
    """GROUP BY counts without fetching rows.

    cols: a column name or list of column names. Returns e.g.
    [{"engine": "cve", "severity": "HIGH", "n": 3}, ...].
    """
    s = _SCHEMA[entity]
    cols = [cols] if isinstance(cols, str) else list(cols)
    _check_columns(cols)
    where, vals = _where(entity, filters)
    if _in:
        _check_filters(entity, _in)
        extra = [f"{k}::text = ANY(%s)" for k in _in]
        where = (where + " AND " if where else "WHERE ") + " AND ".join(extra)
        vals = vals + [[str(x) for x in v] for v in _in.values()]
    group = ", ".join(cols)
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT {group}, COUNT(*) FROM {s['table']} {where} GROUP BY {group}", vals)
        rows = cur.fetchall()
    return [dict(zip(cols + ["n"], r)) for r in rows]


def count(entity: str, **filters: Any) -> int:
    """SELECT COUNT(*) with key-column equality filters (no row transfer)."""
    s = _SCHEMA[entity]
    where, vals = _where(entity, filters)
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT COUNT(*) FROM {s['table']} {where}", vals)
        r = cur.fetchone()
    return int(r[0]) if r else 0


MAX_PAGE_SIZE = 200


def _sortable(entity: str) -> set:
    """Columns a caller may ORDER BY: scalar key columns + pk + created_at (never JSONB blobs)."""
    s = _SCHEMA[entity]
    return {s["pk"], "created_at"} | set(s["keys"])


def select_page(entity: str, columns: Optional[List[str]] = None, *, page: int = 1,
                page_size: int = 50, sort: Optional[str] = None, order: str = "desc",
                q: Optional[str] = None, search: Tuple[str, ...] = (),
                default_sort: str = "created_at", **filters: Any) -> Tuple[List[Dict[str, Any]], int]:
    """One page of rows plus the total matching count, all computed in SQL.

    - filters: key-column equality (case-insensitive), always bound parameters.
    - sort: must be in the entity's sortable whitelist, otherwise ValueError;
      the identifier is only ever interpolated after that whitelist check.
    - q: case-insensitive substring match (ILIKE, wildcards escaped) OR-ed over
      the `search` columns, which must be whitelisted key columns.
    - columns=None returns full (decrypted) record dicts from `data`.
    Raises ValueError on any illegal argument (callers map it to HTTP 400).
    """
    s = _SCHEMA[entity]
    allowed = _sortable(entity)
    sort = sort or default_sort
    if sort not in allowed:
        raise ValueError(f"illegal sort column: {sort!r}")
    direction = str(order or "desc").upper()
    if direction not in ("ASC", "DESC"):
        raise ValueError(f"illegal order: {order!r}")
    page = max(1, int(page))
    page_size = max(1, min(int(page_size), MAX_PAGE_SIZE))
    if columns is not None:
        _check_columns(columns)
    _check_filters(entity, filters)
    clauses = [f"UPPER({k}::text)=UPPER(%s)" for k in filters]
    vals: List[Any] = list(filters.values())
    if q:
        bad = [c for c in search if c not in allowed]
        if bad:
            raise ValueError(f"illegal search column(s): {bad}")
        if search:
            esc = str(q).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append("(" + " OR ".join(f"{c}::text ILIKE %s" for c in search) + ")")
            vals += [f"%{esc}%"] * len(search)
    oc, ov = _org_clause()
    clauses += oc
    vals += ov
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    proj = "data" if columns is None else ", ".join(columns)
    pk = s["pk"]
    tie = "" if sort == pk else f", {s['table']}.{pk} ASC"
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT COUNT(*) FROM {s['table']} {where}", vals)
        total = int((cur.fetchone() or [0])[0])
        cur.execute(f"SELECT {proj} FROM {s['table']} {where} ORDER BY {s['table']}.{sort} {direction}{tie} "
                    f"LIMIT {page_size} OFFSET {(page - 1) * page_size}", vals)
        rows = cur.fetchall()
    if columns is None:
        return [_decrypt_record(entity, dict(r[0] or {})) for r in rows], total
    keys = [_select_key(c) for c in columns]
    out = [dict(zip(keys, r)) for r in rows]
    if _ENCRYPTED.get(entity):
        out = [_decrypt_record(entity, r) for r in out]
    return out, total


def _select_key(col: str) -> str:
    """Dict key for a projected column; supports 'expr AS alias' projections."""
    low = col.lower()
    if " as " in low:
        return col[low.index(" as ") + 4:].strip().strip('"')
    return col.split(".")[-1].strip('"')


def select(entity: str, columns: List[str], order: str = "created_at DESC",
           limit: int = 50, offset: int = 0, **filters: Any) -> List[Dict[str, Any]]:
    """Projected list read — only the given columns, no heavy inflate.

    Plain JSONB columns come back parsed. Items may also be restricted
    projections with aliases (e.g. "data->'flat_ir' AS flat_ir"). Columns and
    ordering are validated; filter values are always bound parameters.
    """
    s = _SCHEMA[entity]
    _check_columns(columns)
    if not _ORDER_RE.match(order):
        raise ValueError(f"illegal order: {order!r}")
    cols = ", ".join(columns)
    keys = [_select_key(c) for c in columns]
    where, vals = _where(entity, filters)
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT {cols} FROM {s['table']} {where} ORDER BY {order} "
                    f"LIMIT {int(limit)} OFFSET {int(offset)}", vals)
        rows = cur.fetchall()
    out = [dict(zip(keys, r)) for r in rows]
    if _ENCRYPTED.get(entity):
        out = [_decrypt_record(entity, r) for r in out]
    return out


def find(entity: str, order: str = "ASC", **filters: Any) -> List[Dict[str, Any]]:
    """List records; filters are key-column equalities (case-insensitive for text)."""
    s = _SCHEMA[entity]
    if str(order).upper() not in ("ASC", "DESC"):
        raise ValueError(f"illegal order: {order!r}")
    where, vals = _where(entity, filters)
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT data FROM {s['table']} {where} ORDER BY created_at {order}", vals)
        rows = cur.fetchall()
    return [_decrypt_record(entity, d) for (d,) in rows]


def update(entity: str, pk_value: str, patch: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rec = get(entity, pk_value)
    if rec is None:
        return None
    rec.update(patch)
    return save(entity, rec)


def delete(entity: str, pk_value: str) -> bool:
    s = _SCHEMA[entity]
    oc, ov = _org_clause()
    where = " AND ".join([f"{s['pk']}=%s"] + oc)
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"DELETE FROM {s['table']} WHERE {where}", [pk_value] + ov)
        return cur.rowcount > 0


def clear(entity: str) -> int:
    """Delete every row of the CURRENT org (never other tenants)."""
    s = _SCHEMA[entity]
    oc, ov = _org_clause()
    where = f"WHERE {' AND '.join(oc)}" if oc else ""
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"DELETE FROM {s['table']} {where}", ov)
        return cur.rowcount


def _inflate(entity: str, data: Any, pk_value: str) -> Dict[str, Any]:
    rec = _decrypt_record(entity, dict(data or {}))
    if entity == "audits":
        rec["findings"] = find("findings", audit_id=rec.get("audit_id", pk_value))
    if entity == "reports":
        oc, ov = _org_clause()
        where = " AND ".join(["report_id=%s"] + oc)
        with dbmod.get_conn() as conn:
            cur = conn.cursor()
            cur.execute(f"SELECT pdf FROM reports WHERE {where}", [pk_value] + ov)
            r = cur.fetchone()
        rec["pdf"] = bytes(r[0]) if r and r[0] is not None else b""
    return rec
