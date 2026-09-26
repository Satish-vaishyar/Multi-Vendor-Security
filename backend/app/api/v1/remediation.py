"""Remediation: GET plan / approve / apply-dry-run (api.md §26-27).

Safety: Generate -> Review -> Approve -> Apply(simulated) -> Validate(re-audit).
Never touches live devices.
"""
from __future__ import annotations
import time
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core import config as cfg
from app.core import persist as db
from app.core import store
from app.services.integration import okf_layer

router = APIRouter(prefix="/api/v1/remediation", tags=["remediation"])


@router.get("/{finding_id}")
def get_plan(finding_id: str):
    f = db.get("findings", finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    audit = db.get("audits", f.get("audit_id", "")) or {}
    vendor = str(((audit.get("vendor") or {}).get("vendor_id")) or "unknown").lower()
    okf = okf_layer()
    entry = okf["rem"].index.get(f.get("control_id", ""), {})
    vendors = entry.get("vendors", {}) or {}
    vend = vendors.get(vendor, {}) or next(iter(vendors.values()), {})
    cmds = vend.get("commands", [])
    if not cmds and f.get("engine") == "cve":
        fixed = (f.get("remediation") or {}).get("fixed_version")
        cmds = [f"upgrade to {fixed} (vendor-validated)"] if fixed else ["follow vendor advisory upgrade path"]
    steps = [{"order": i + 1, "command": c} for i, c in enumerate(cmds)]
    return cfg.ok({"finding_id": finding_id, "vendor": vendor,
                   "platform": (audit.get("vendor") or {}).get("platform", ""),
                   "steps": steps, "validation": vend.get("validation", ["show running-config"]),
                   "rollback_available": bool(vend.get("rollback")), "approval_required": True})


class ApproveBody(BaseModel):
    approved_by: str = "admin"  # callers send the real reviewer; default keeps old clients working
    comment: str = ""


@router.post("/{finding_id}/approve")
def approve(finding_id: str, body: ApproveBody):
    if not db.get("findings", finding_id):
        raise HTTPException(404, "Finding not found")
    rid = store.nid("REM")
    rec = {"id": rid, "finding_id": finding_id, "status": "APPROVED",
           "approved_by": body.approved_by, "comment": body.comment,
           "approved_at": store.now(), "created_at": store.now()}
    db.save("remediations", rec)
    return cfg.ok(rec, "Remediation approved")


class ApplyBody(BaseModel):
    id: str = ""  # approval id from /approve
    updated_config_text: str = ""


@router.post("/{finding_id}/apply")
def apply(finding_id: str, body: ApplyBody):
    ap = db.get("remediations", body.id)
    if not ap or ap.get("finding_id") != finding_id or ap.get("status") != "APPROVED":
        raise HTTPException(400, "Approve first via POST /remediation/{finding_id}/approve")
    result: dict = {"finding_id": finding_id, "mode": "SIMULATION", "device_touched": False,
                    "applied_at": store.now()}
    if body.updated_config_text:
        # closed-loop: re-ingest + re-run engines on the fixed config
        from app.services import audit_service
        f = db.get("findings", finding_id)
        assert f is not None
        audit = db.get("audits", f.get("audit_id", "")) or {}
        asset = db.get("assets", f.get("asset_id", "")) or {}
        record = audit_service.run_audit(
            asset_id=f.get("asset_id", ""), configuration_id=f.get("audit_id", ""),
            config_text=body.updated_config_text,
            frameworks=audit.get("frameworks", ["CIS", "NIST", "STIG", "ISO27001"]),
            asset_criticality=str(asset.get("criticality") or "MEDIUM"), detected=audit.get("vendor"))
        same = [x for x in record["findings"]
                if x.get("control_id") == f.get("control_id") and x.get("type") == f.get("type")]
        result["re_audit_status"] = same[0]["status"] if same else "UNKNOWN"
        result["verified_fixed"] = result["re_audit_status"] == "PASS"
        result["re_audit_id"] = record["audit_id"]
    db.update("remediations", body.id, {"status": "APPLIED_SIMULATED"})
    return cfg.ok(result, "Dry-run apply completed (simulation)")
