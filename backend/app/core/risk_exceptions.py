"""Risk acceptance ("exceptions"): a finding on an asset can be formally accepted until a date.

Workflow: AUDITOR requests -> a *different* APPROVER/ADMIN approves or rejects (four-eyes) -> it is only
effective while APPROVED and unexpired -> anyone with approver rights can revoke. Exceptions never change
scores or hide findings: exports and reports show the finding with its acceptance so an auditor sees both.
"""
from __future__ import annotations
import uuid
from typing import Any, Dict, List, Optional, Set

from app.core import config as cfg
from app.core import db as dbmod
from app.core import tenancy

_COLS = ("exception_id, asset_id, finding_key, reason, status, requested_by, decided_by, decision_comment, "
         "extract(epoch from expires_at) AS expires_at, extract(epoch from created_at) AS created_at, "
         "extract(epoch from decided_at) AS decided_at, (status='APPROVED' AND expires_at > now()) AS active")


class ExceptionError(ValueError):
    pass


class Forbidden(PermissionError):
    pass


def finding_key(f: Dict[str, Any]) -> str:
    src = f.get("source") if isinstance(f.get("source"), dict) else {}
    ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
    return str(f.get("control_id") or src.get("cve") or src.get("rule") or src.get("control")
               or ev.get("rule_id") or f.get("title") or "")


def _rows(cur) -> List[Dict[str, Any]]:
    cols = [d[0] for d in cur.description]
    out = []
    for r in cur.fetchall():
        d = dict(zip(cols, r))
        for k in ("expires_at", "created_at", "decided_at"):
            d[k] = float(d[k]) if d.get(k) is not None else None
        out.append(d)
    return out


def request(asset_id: str, finding_key_: str, reason: str, days: int, requested_by: str) -> Dict[str, Any]:
    reason, key = (reason or "").strip(), (finding_key_ or "").strip()
    if len(reason) < 10:
        raise ExceptionError("a reason of at least 10 characters is required (it is shown to auditors)")
    if not key or not asset_id:
        raise ExceptionError("asset_id and finding_key are required")
    if not 1 <= int(days) <= cfg.EXCEPTION_MAX_DAYS:
        raise ExceptionError(f"expiry must be between 1 and {cfg.EXCEPTION_MAX_DAYS} days - acceptances must not be open-ended")
    eid = "EXC-" + uuid.uuid4().hex[:10].upper()
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("SELECT 1 FROM assets WHERE asset_id=%s AND org_id=%s", (asset_id, tenancy.current_org()))
        if not cur.fetchone():
            raise ExceptionError("asset not found")
        cur.execute("SELECT 1 FROM finding_exceptions WHERE org_id=%s AND asset_id=%s AND finding_key=%s "
                    "AND status IN ('PENDING','APPROVED') AND expires_at > now()", (tenancy.current_org(), asset_id, key))
        if cur.fetchone():
            raise ExceptionError("an open or approved exception already exists for this finding on this asset")
        cur.execute("INSERT INTO finding_exceptions (exception_id, org_id, asset_id, finding_key, reason, requested_by, expires_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s, now() + make_interval(days => %s))",
                    (eid, tenancy.current_org(), asset_id, key, reason[:2000], requested_by, int(days)))
    return get(eid) or {}


def get(exception_id: str) -> Optional[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(f"SELECT {_COLS} FROM finding_exceptions WHERE exception_id=%s AND org_id=%s",
                    (exception_id, tenancy.current_org()))
        r = _rows(cur)
        return r[0] if r else None


def list_all(status: Optional[str] = None, asset_id: Optional[str] = None) -> List[Dict[str, Any]]:
    clauses, vals = ["org_id=%s"], [tenancy.current_org()]
    if status:
        clauses.append("status=%s")
        vals.append(status.upper())
    if asset_id:
        clauses.append("asset_id=%s")
        vals.append(asset_id)
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(f"SELECT {_COLS} FROM finding_exceptions WHERE {' AND '.join(clauses)} ORDER BY created_at DESC LIMIT 500", vals)
        return _rows(cur)


def decide(exception_id: str, decision: str, actor: str, comment: str = "") -> Dict[str, Any]:
    """decision: APPROVED | REJECTED | REVOKED. Four-eyes: the requester can never approve their own request."""
    cur_row = get(exception_id)
    if not cur_row:
        raise LookupError("exception not found")
    if decision == "REVOKED":
        if cur_row["status"] not in ("APPROVED", "PENDING"):
            raise ExceptionError(f"cannot revoke an exception that is {cur_row['status']}")
    else:
        if cur_row["status"] != "PENDING":
            raise ExceptionError(f"exception is already {cur_row['status']}")
        if decision == "APPROVED" and cur_row["requested_by"] == actor:
            raise Forbidden("four-eyes rule: you cannot approve your own exception request")
        if cur_row["expires_at"] <= __import__("time").time():
            raise ExceptionError("request has already expired")
    with dbmod.get_conn() as conn:
        conn.cursor().execute(  # type: ignore[attr-defined]
            "UPDATE finding_exceptions SET status=%s, decided_by=%s, decision_comment=%s, decided_at=now() "
            "WHERE exception_id=%s AND org_id=%s", (decision, actor, (comment or "")[:1000], exception_id, tenancy.current_org()))
    return get(exception_id) or {}


def active_keys(asset_id: Optional[str] = None) -> Dict[tuple, Dict[str, Any]]:
    """{(asset_id, finding_key): exception} for approved, unexpired exceptions of the current org."""
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        q = f"SELECT {_COLS} FROM finding_exceptions WHERE org_id=%s AND status='APPROVED' AND expires_at > now()"
        vals: list = [tenancy.current_org()]
        if asset_id:
            q += " AND asset_id=%s"
            vals.append(asset_id)
        cur.execute(q, vals)
        return {(r["asset_id"], r["finding_key"]): r for r in _rows(cur)}


def active_set(asset_id: Optional[str] = None) -> Set[tuple]:
    return set(active_keys(asset_id))
