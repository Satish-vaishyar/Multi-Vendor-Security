"""Lab verification of remediation templates - evidence, not assertion.

A fix template is shipped as "documented, not lab-verified". It becomes "lab-verified" for a customer only through this
workflow: in a lab (or a maintenance window) the operator captures the device configuration BEFORE the fix, AFTER it
and, ideally, AFTER the rollback, and uploads the three. The product re-audits each one against the control and records
the outcome itself, so a verification can never be typed in by hand:

    before  must FAIL         (the problem really was there)
    after   must PASS         (the fix removed it)
    rollback (optional) must FAIL again   (the rollback really restores the old state)

Anything else is stored as FAILED with the reason, and never shows up as verified.
"""
from __future__ import annotations
import hashlib
import uuid
from typing import Any, Dict, List, Optional

from psycopg.types.json import Jsonb

from app.core import db as dbmod
from app.core import persist, tenancy
from app.services import corpus_eval


class VerificationError(ValueError):
    pass


def _statuses(config_id: str, control_id: str) -> Dict[str, Any]:
    conf = persist.get("configurations", config_id)
    if not conf:
        raise VerificationError(f"configuration {config_id} not found")
    det, status = corpus_eval.control_statuses(conf["config_text"])
    if control_id not in status:
        raise VerificationError(f"control {control_id} is not part of the loaded control set")
    return {"configuration_id": config_id, "status": status[control_id], "vendor": det["vendor_id"],
            "platform": str(det.get("platform") or ""), "version": det.get("version") or "",
            "sha256": hashlib.sha256(conf["config_text"].encode("utf-8")).hexdigest()}


def verify(*, control_id: str, before_id: str, after_id: str, rollback_id: Optional[str] = None,
           os_version: str = "", device_model: str = "", verified_by: Optional[str] = None) -> Dict[str, Any]:
    if len({x for x in (before_id, after_id, rollback_id) if x}) != len([x for x in (before_id, after_id, rollback_id) if x]):
        raise VerificationError("before / after / rollback must be three different configurations")
    b, a = _statuses(before_id, control_id), _statuses(after_id, control_id)
    r = _statuses(rollback_id, control_id) if rollback_id else None
    if b["vendor"] != a["vendor"] or (r and r["vendor"] != b["vendor"]):
        raise VerificationError("the configurations are not from the same vendor")
    if b["sha256"] == a["sha256"]:
        raise VerificationError("the before and after configurations are identical: nothing was changed")
    problems: List[str] = []
    if b["status"] != "FAIL":
        problems.append(f"before the fix the control was {b['status']}, not FAIL (nothing to fix)")
    if a["status"] != "PASS":
        problems.append(f"after the fix the control is {a['status']}, not PASS (the fix did not work)")
    if r is not None and r["status"] != "FAIL":
        problems.append(f"after the rollback the control is {r['status']}, not FAIL (the rollback did not restore the old state)")
    ok = not problems
    vid = "FXV-" + uuid.uuid4().hex[:10].upper()
    org = tenancy.current_org()
    rec = {"verification_id": vid, "control_id": control_id, "vendor": b["vendor"], "platform": b["platform"],
           "os_version": os_version or b["version"], "device_model": device_model, "status": "VERIFIED" if ok else "FAILED",
           "before_status": b["status"], "after_status": a["status"], "rollback_status": r["status"] if r else None,
           "rollback_tested": r is not None and r["status"] == "FAIL", "reason": "; ".join(problems) or None,
           "evidence": {"before": b, "after": a, "rollback": r}, "verified_by": verified_by}
    with dbmod.get_conn() as conn:
        conn.cursor().execute(  # type: ignore[attr-defined]
            "INSERT INTO fix_verifications (verification_id, org_id, control_id, vendor, platform, os_version, device_model, status, "
            "before_status, after_status, rollback_status, rollback_tested, reason, evidence, verified_by) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (vid, org, control_id, rec["vendor"], rec["platform"], rec["os_version"], device_model[:120], rec["status"],
             rec["before_status"], rec["after_status"], rec["rollback_status"], rec["rollback_tested"], rec["reason"],
             Jsonb(rec["evidence"]), verified_by))
    return rec


_COLS = ("verification_id, control_id, vendor, platform, os_version, device_model, status, before_status, after_status, "
         "rollback_status, rollback_tested, reason, verified_by, created_at")


def _row(r) -> Dict[str, Any]:  # type: ignore[no-untyped-def]
    k = _COLS.replace(" ", "").split(",")
    d = dict(zip(k, r))
    d["created_at"] = d["created_at"].isoformat()
    return d


def list_verifications(control_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    sql, params = f"SELECT {_COLS} FROM fix_verifications WHERE org_id=%s", [tenancy.current_org()]
    if control_id:
        sql, params = sql + " AND control_id=%s", params + [control_id]
    with dbmod.get_conn() as conn:
        c = conn.cursor()  # type: ignore[attr-defined]
        c.execute(sql + " ORDER BY created_at DESC LIMIT %s", params + [min(max(limit, 1), 500)])
        return [_row(r) for r in c.fetchall()]


def lookup(control_id: str, vendor: str, platform: str = "") -> Optional[Dict[str, Any]]:
    """Latest VERIFIED record for this control on this vendor (platform must match when the record has one)."""
    with dbmod.get_conn() as conn:
        c = conn.cursor()  # type: ignore[attr-defined]
        c.execute(f"SELECT {_COLS} FROM fix_verifications WHERE org_id=%s AND control_id=%s AND vendor=%s AND status='VERIFIED' "
                  "ORDER BY created_at DESC LIMIT 20", (tenancy.current_org(), control_id, vendor.lower()))
        rows = [_row(r) for r in c.fetchall()]
    for r in rows:
        if not r["platform"] or not platform or r["platform"].lower() == platform.lower():
            return r
    return None


def describe(rec: Dict[str, Any]) -> str:
    model = f" on {rec['device_model']}" if rec.get("device_model") else ""
    ver = f" {rec['os_version']}" if rec.get("os_version") else ""
    rb = "rollback tested" if rec.get("rollback_tested") else "rollback NOT tested"
    return (f"Lab-verified{model}{ver} on {rec['created_at'][:10]} by {rec.get('verified_by') or 'an operator'}: "
            f"control FAIL before, PASS after the fix; {rb}. Applies to that platform and version - re-verify for others.")
