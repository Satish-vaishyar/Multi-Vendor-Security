"""FastAPI router for OKF endpoints (api.md §30 + evidence §31 + remediation §26-27)."""
from __future__ import annotations
import hashlib
import time
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from .control_kb import ControlKB, FrameworkRegistry, Crosswalk
from .property_registry import PropertyRegistry
from .engines import ComplianceEngine
from .knowledge_extras import MappingRegistry, RemediationKB, RiskEngine, nest_flat_ir
from .learning_engine import LearningEngine

router = APIRouter(prefix="/api/v1/okf", tags=["okf"])

props = PropertyRegistry().load()
ckb = ControlKB().load()
fwk = FrameworkRegistry().load()
xwalk = Crosswalk().load()
rem = RemediationKB().load()
maps = MappingRegistry().load()
learn = LearningEngine(maps)

# In-memory audit store (reproducibility fields per arch §55-56; Postgres in prod).
AUDITS: Dict[str, Dict[str, Any]] = {}
REM_APPROVALS: Dict[str, Dict[str, Any]] = {}


def _ok(data: Any, message: str = "ok") -> Dict[str, Any]:
    return {"success": True, "data": data, "message": message}


@router.get("/properties")
def list_properties(category: Optional[str] = None):
    items = props.all()
    if category:
        items = [p for p in items if p.category == category]
    return _ok([p.model_dump() for p in items])


@router.get("/controls")
def list_controls(framework: Optional[str] = None, category: Optional[str] = None,
                  severity: Optional[str] = None):
    items = ckb.all()
    if framework:
        items = [c for c in items if framework.upper() in (k.upper() for k in c.frameworks)]
    if category:
        items = [c for c in items if c.category == category]
    if severity:
        items = [c for c in items if c.severity == severity.upper()]
    return _ok([c.model_dump() for c in items])


@router.get("/controls/{control_id}")
def get_control(control_id: str):
    c = ckb.controls.get(control_id)
    if not c:
        return {"success": False, "error": {"code": "NOT_FOUND", "message": control_id}}
    d = c.model_dump()
    d["remediation"] = rem.index.get(control_id, {})
    return _ok(d)


@router.get("/crosswalk/{control_id}")
def crosswalk(control_id: str):
    return _ok(xwalk.for_control(control_id, ckb.controls))


@router.get("/frameworks")
def frameworks():
    return _ok([f.model_dump() for f in fwk.frameworks.values()])


class AuditBody(BaseModel):
    asset_id: str = "ASSET-001"
    vendor: str = "cisco"
    platform: str = "ios-xe"
    config_text: str = ""
    frameworks: List[str] = ["CIS", "NIST", "STIG", "ISO27001"]
    asset_criticality: str = "HIGH"


@router.post("/audit")
def audit(body: AuditBody):
    parsed = learn.audit_config(body.config_text, vendor=body.vendor.lower())
    controls = ckb.for_frameworks(body.frameworks)
    eng = ComplianceEngine(controls, {k: v for k, v in rem.index.items()})
    findings = eng.evaluate(parsed["nested_ir"], asset_id=body.asset_id)
    for f in findings:  # attach risk
        f.remediation = {**(f.remediation if isinstance(f.remediation, dict) else {}),
                         "risk": RiskEngine.score_finding(f, body.asset_criticality)}
    sc = ComplianceEngine.score(findings)
    by_fw: Dict[str, Dict[str, Any]] = {}
    for fw in body.frameworks:
        rel = [f for f in findings if fw.upper() in (k.upper() for k in (f.frameworks or {}))]
        by_fw[fw] = ComplianceEngine.score(rel) if rel else {"compliance_score": 0.0, "total": 0}
    audit_id = f"AUD-{hashlib.sha256(body.config_text.encode()).hexdigest()[:8].upper()}"
    AUDITS[audit_id] = {
        "audit_id": audit_id, "asset_id": body.asset_id, "vendor": body.vendor,
        "config_hash": hashlib.sha256(body.config_text.encode()).hexdigest(),
        "parser_version": "1.0", "mapping_version": "1.0",
        "control_pack_version": "1.0", "okf_version": "1.0.0",
        "timestamp": time.time(), "summary": sc, "by_framework": by_fw,
        "findings": [f.model_dump() for f in findings],
        "canonical_ir": parsed["nested_ir"], "provenance": parsed.get("provenance", {}),
        "unknown_lines": parsed["unknown_lines"],
    }
    return _ok({**AUDITS[audit_id], "llm_offline": parsed["offline"]}, "Audit completed")


@router.get("/audit/{audit_id}/evidence")
def audit_evidence(audit_id: str):
    """Why-did-this-fail evidence chain (api.md §31): control → property →
    observed/expected → source line. Stored per audit for reproducibility."""
    a = AUDITS.get(audit_id)
    if not a:
        return {"success": False, "error": {"code": "NOT_FOUND", "message": audit_id}}
    items = []
    prov = a.get("provenance", {})
    for f in a["findings"]:
        ev = f.get("evidence", {}) if isinstance(f.get("evidence"), dict) else {}
        prop = ev.get("property", "")
        src = prov.get(prop, {})
        items.append({
            "control_id": f["control_id"], "property": prop,
            "observed_value": ev.get("observed_value"),
            "expected_value": ev.get("expected_value"),
            "status": f["status"],
            "source": {"line": src.get("line", ""), "line_no": src.get("line_no"),
                       "confidence": src.get("confidence")},
        })
    return _ok({"audit_id": audit_id, "items": items})


@router.get("/remediation/{control_id}")
def get_remediation(control_id: str, vendor: str = "cisco"):
    entry = rem.index.get(control_id)
    if not entry:
        return {"success": False, "error": {"code": "NOT_FOUND", "message": control_id}}
    v = entry.get("vendors", {}).get(vendor.lower(), {})
    return _ok({"control_id": control_id, "vendor": vendor,
                "title": entry.get("title", ""), **v,
                "approval_required": v.get("approval_required", True),
                "rollback_available": bool(v.get("rollback"))})


@router.post("/remediation/{control_id}/approve")
def remediation_approve(control_id: str, body: Dict[str, Any] = {}):
    rid = f"REM-{control_id}-{int(time.time()) % 100000}"
    REM_APPROVALS[rid] = {"approval_id": rid, "control_id": control_id,
                          "approved_by": body.get("approved_by", "admin"),
                          "comment": body.get("comment", ""), "status": "APPROVED"}
    return _ok(REM_APPROVALS[rid], "Remediation approved (human gate)")


class ApplyBody(BaseModel):
    approval_id: str = ""
    updated_config_text: str = ""  # optional: re-audit this to verify the fix


@router.post("/remediation/{control_id}/apply")
def remediation_apply(control_id: str, body: ApplyBody):
    """Dry-run simulation only (never touches devices): returns commands that
    WOULD run, validation steps, and — if updated_config_text is supplied —
    a re-audit diff proving the fix (closed-loop per arch §32-33)."""
    ap = REM_APPROVALS.get(body.approval_id)
    if not ap or ap["control_id"] != control_id:
        return {"success": False, "error": {"code": "APPROVAL_REQUIRED",
                "message": "Approve first via POST /remediation/{id}/approve"}}
    entry = rem.index.get(control_id, {})
    vendor = "cisco"
    cmds = entry.get("vendors", {}).get(vendor, {}).get("commands", [])
    result: Dict[str, Any] = {"control_id": control_id, "mode": "SIMULATION",
        "commands_that_would_run": cmds,
        "validation": entry.get("vendors", {}).get(vendor, {}).get("validation", []),
        "device_touched": False}
    if body.updated_config_text:
        parsed = learn.audit_config(body.updated_config_text, vendor=vendor)
        findings = ComplianceEngine(ckb.all()).evaluate(parsed["nested_ir"])
        st = next((f.status for f in findings if f.control_id == control_id), "UNKNOWN")
        result["re_audit_status"] = st
        result["verified_fixed"] = st == "PASS"
    return _ok(result, "Dry-run apply completed (simulation)")


class SuggestBody(BaseModel):
    raw_command: str
    vendor: str = "unknown"
    context: List[str] = []


@router.post("/training/suggest")
def training_suggest(body: SuggestBody):
    return _ok(learn.suggest(body.raw_command, body.vendor, body.context))


class ApproveBody(BaseModel):
    vendor: str
    platform: str = "any"
    pattern: str
    canonical_property: str
    canonical_value: Any = None


@router.post("/training/approve")
def training_approve(body: ApproveBody):
    m = learn.approve(body.vendor, body.platform, body.pattern,
                      body.canonical_property, body.canonical_value)
    maps.load()
    return _ok(m.model_dump(), "Mapping approved and registry updated")
