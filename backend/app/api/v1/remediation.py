"""Remediation: GET plan / approve / apply-dry-run (api.md §26-27).

Safety: Generate -> Review -> Approve -> Apply(simulated) -> Validate(re-audit).
Never touches live devices. Every apply runs with ``device_touched=False``
and, when a candidate config is supplied, re-audits it to prove the fix.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.core import config as cfg
from app.core import persist as db
from app.core import store
from app.services.integration import okf_layer

router = APIRouter(prefix="/api/v1/remediation", tags=["remediation"])


def _finding_or_404(finding_id: str) -> dict:
    f = db.get("findings", finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    return f


def _audit_vendor(audit_id: str) -> dict:
    """Vendor/platform/version snapshot stored on the audit record."""
    if not audit_id:
        return {}
    try:
        rows = db.select("audits", ["vendor"], limit=1, audit_id=audit_id)
    except Exception:
        return {}
    if not rows:
        return {}
    return (rows[0].get("vendor") or {}) if isinstance(rows[0], dict) else {}


def _engine_key(f: dict) -> str:
    return str(f.get("engine") or f.get("type") or "").lower()


def _fallback_steps(f: dict) -> tuple[list[str], str, list[str]]:
    """Per-engine fallback when the OKF KB has no vendor pack.

    Returns (commands, source, validation).
    """
    eng = _engine_key(f)
    rem = f.get("remediation") or {}
    detail = rem.get("detail") if isinstance(rem.get("detail"), dict) else {}
    if eng == "cve" or f.get("type") == "VULNERABILITY":
        fixed = rem.get("fixed_version")
        cve = (f.get("source") or {}).get("cve", "") if isinstance(f.get("source"), dict) else ""
        ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
        product = str(ev.get("product") or "")
        installed = str(ev.get("installed_version") or ev.get("observed") or "")
        refs: list[str] = list(rem.get("references") or ev.get("references") or [])
        if fixed:
            what = f"Upgrade {product + ' ' if product else ''}{installed + ' ' if installed else ''}to vendor-validated version {fixed}".replace("  ", " ")
            return ([what,
                     "Schedule a maintenance window, back up running-config, upgrade via the vendor image, reload if required",
                     "Verify with `show version` (installed version must be at/above the fixed release), then re-run audit"],
                    "cve-advisory",
                    ["Re-run audit: CVE status should be NOT_AFFECTED"])
        # No fixed release in KB — never leave the engineer with a bare
        # "follow the advisory" line. Name the product/version and point at
        # the actual advisory URLs stored on the finding.
        first_ref = f" Advisory: {refs[0]}" if refs else ""
        return ([f"No fixed release recorded for {cve or 'this CVE'}{f' ({product} {installed})' if product or installed else ''}."
                 f"{first_ref} Open the advisory link(s) below, find the fixed release for your train, upgrade to it.",
                 "Back up running-config first, upgrade in a maintenance window, reload if the vendor requires it",
                 "Verify with `show version`, then re-run audit to confirm NOT_AFFECTED"],
                "cve-advisory",
                ["Re-run audit: CVE status should be NOT_AFFECTED"])
    if eng == "pqc":
        migration = rem.get("migration") or (detail.get("migration") if detail else "")
        observed = (f.get("evidence") or {}).get("observed") if isinstance(f.get("evidence"), dict) else {}
        algo = (observed.get("algorithm") if isinstance(observed, dict) else "") or f.get("title", "")
        cmds = [f"Migrate {algo} per migration guidance"] if algo else ["Migrate weak crypto to PQC-safe algorithms"]
        if migration:
            cmds.append(f"Guidance: {migration}")
        cmds.append("Re-run audit to confirm PQC readiness improved")
        return (cmds, "pqc-migration",
                ["Re-run audit: PQC readiness score should increase"])
    if eng == "security":
        prop = ""
        ev = f.get("evidence") or {}
        if isinstance(ev, dict):
            prop = str(ev.get("property") or "")
        title = str(f.get("title") or "")
        what = prop or title or "this exposure"
        return ([f"Harden {what} per vendor hardening guide (disable cleartext services, enforce AAA/MFA)",
                 "Restrict management-plane access (ACL / jump host) and re-run audit"],
                "security-analytics",
                ["Re-run audit: anomaly should clear"])
    # compliance / generic — ground every step in the stored rule evidence
    # so the engineer sees the exact property/value, never a bare placeholder.
    control = str(f.get("control_id") or "")
    title = str(f.get("title") or control or "this control")
    cmds: list[str] = []
    if isinstance(detail, dict):
        for k in ("commands", "fix_commands", "steps"):
            v = detail.get(k)
            if isinstance(v, list) and v:
                cmds = [str(c) for c in v]
                break
        if not cmds and detail.get("recommendation"):
            cmds = [str(detail["recommendation"])]
    if not cmds:
        ev2 = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
        prop = str(ev2.get("property") or "")
        obs = ev2.get("observed_value", ev2.get("observed", "—"))
        exp = ev2.get("expected_value", ev2.get("expected", "—"))
        op = str(ev2.get("operator") or "")
        if prop and prop != "—":
            cmds = [f"Set {prop} to {exp} (currently {obs})"
                    f"{f' — rule {op}' if op and op != '—' else ''} to satisfy '{title}' ({control or 'control'})",
                    "Re-run audit to confirm the control passes"]
        else:
            cmds = [f"Remediate '{title}' ({control or 'control'}): apply the vendor hardening-guide setting for this control",
                    "Re-run audit to confirm the control passes"]
    return (cmds, "generic", ["show running-config", "Re-run audit: control status should be PASS"])


@router.get("/{finding_id}")
def get_plan(finding_id: str):
    f = _finding_or_404(finding_id)
    vendor_info = _audit_vendor(str(f.get("audit_id", "")))
    vendor = str(vendor_info.get("vendor_id") or "unknown").lower()
    platform = str(vendor_info.get("platform") or "")
    version = str(vendor_info.get("version") or "")

    okf = okf_layer()
    entry = (okf["rem"].index or {}).get(str(f.get("control_id") or ""), {})
    vendors = (entry.get("vendors") or {}) if isinstance(entry, dict) else {}
    vend = vendors.get(vendor, {}) or next(iter(vendors.values()), {})
    if not isinstance(vend, dict):
        vend = {}

    cmds: list[str] = list(vend.get("commands") or [])
    source = "okf-vendor" if cmds else ""
    validation: list[str] = list(vend.get("validation") or [])
    rollback: list[str] = list(vend.get("rollback") or [])
    approval_required = bool(vend.get("approval_required", True))
    fix_title = str(vend.get("title") or entry.get("title") or f.get("title") or "")

    if not cmds:
        cmds, source, fb_validation = _fallback_steps(f)
        if not validation:
            validation = fb_validation
        if not fix_title:
            fix_title = str(f.get("title") or "")
    else:
        source = "okf-vendor"

    steps = [{"order": i + 1, "command": c} for i, c in enumerate(cmds)]
    _rem_all = f.get("remediation") if isinstance(f.get("remediation"), dict) else {}
    _ev_all = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
    _refs_out: list[str] = []
    for _r in list(_rem_all.get("references") or _ev_all.get("references") or []):
        _u = _r if isinstance(_r, str) else (_r.get("url") if isinstance(_r, dict) else str(_r))
        if _u and _u not in _refs_out:
            _refs_out.append(_u)
    return cfg.ok({"finding_id": finding_id,
                   "title": str(f.get("title") or ""),
                   "severity": str(f.get("severity") or "UNKNOWN"),
                   "engine": str(f.get("engine") or ""),
                   "type": str(f.get("type") or ""),
                   "control_id": str(f.get("control_id") or ""),
                   "status": str(f.get("status") or ""),
                   "asset_id": str(f.get("asset_id") or ""),
                   "audit_id": str(f.get("audit_id") or ""),
                   "fix_title": fix_title,
                   "source": source,
                   "vendor": vendor,
                   "platform": platform,
                   "vendor_version": version,
                   "steps": steps,
                   "validation": validation,
                   "rollback": rollback,
                   "rollback_available": bool(rollback),
                   "approval_required": approval_required,
                   "risk": f.get("risk") or {},
                   "evidence": f.get("evidence") or {},
                   "references": _refs_out,
                   "remediation_detail": f.get("remediation") or {}})


@router.get("/{finding_id}/history")
def history(finding_id: str):
    _finding_or_404(finding_id)
    try:
        items = db.find("remediations", order="DESC", finding_id=finding_id)
    except Exception:
        items = []
    lite = [{"id": r.get("id"), "finding_id": r.get("finding_id"),
             "status": r.get("status"), "approved_by": r.get("approved_by"),
             "comment": r.get("comment", ""), "approved_at": r.get("approved_at"),
             "created_at": r.get("created_at")} for r in items]
    return cfg.ok({"finding_id": finding_id, "items": lite, "total": len(lite)})


class ApproveBody(BaseModel):
    approved_by: str = Field(default="admin", min_length=1)
    comment: str = ""


@router.post("/{finding_id}/approve")
def approve(finding_id: str, body: ApproveBody):
    _finding_or_404(finding_id)
    approved_by = (body.approved_by or "").strip()
    if not approved_by:
        raise HTTPException(400, "approved_by is required")
    rid = store.nid("REM")
    rec = {"id": rid, "finding_id": finding_id, "status": "APPROVED",
           "approved_by": approved_by, "comment": body.comment or "",
           "approved_at": store.now(), "created_at": store.now()}
    db.save("remediations", rec)
    return cfg.ok(rec, "Remediation approved")


class ApplyBody(BaseModel):
    id: str = Field(default="", min_length=1)  # approval id from /approve
    updated_config_text: str = ""


def _same_finding_key(orig: dict, cand: dict) -> bool:
    """Match a re-audit finding to the original across engines.

    Compliance findings key off control_id; CVE off the CVE id; PQC off the
    algorithm; security off the analytic type/property. Falls back to type.
    """
    if (cand.get("engine") or "") != (orig.get("engine") or ""):
        return False
    eng = _engine_key(orig)
    if eng == "compliance":
        return (cand.get("control_id") or "") == (orig.get("control_id") or "")
    if eng == "cve" or orig.get("type") == "VULNERABILITY":
        oc = (orig.get("source") or {}) if isinstance(orig.get("source"), dict) else {}
        cc = (cand.get("source") or {}) if isinstance(cand.get("source"), dict) else {}
        if oc.get("cve") and cc.get("cve"):
            return cc.get("cve") == oc.get("cve")
        return (cand.get("type") or "") == (orig.get("type") or "")
    if eng == "pqc":
        oe = (orig.get("evidence") or {}).get("observed") if isinstance(orig.get("evidence"), dict) else {}
        ce = (cand.get("evidence") or {}).get("observed") if isinstance(cand.get("evidence"), dict) else {}
        oa = oe.get("algorithm") if isinstance(oe, dict) else None
        ca = ce.get("algorithm") if isinstance(ce, dict) else None
        if oa and ca:
            return ca == oa
        return (cand.get("type") or "") == (orig.get("type") or "")
    if eng == "security":
        osrc = (orig.get("source") or {}) if isinstance(orig.get("source"), dict) else {}
        csrc = (cand.get("source") or {}) if isinstance(cand.get("source"), dict) else {}
        if osrc.get("analytics") and csrc.get("analytics"):
            return csrc.get("analytics") == osrc.get("analytics")
        oe = (orig.get("evidence") or {}).get("property") if isinstance(orig.get("evidence"), dict) else ""
        ce = (cand.get("evidence") or {}).get("property") if isinstance(cand.get("evidence"), dict) else ""
        if oe and ce:
            return ce == oe
        return (cand.get("type") or "") == (orig.get("type") or "")
    return (cand.get("type") or "") == (orig.get("type") or "")


@router.post("/{finding_id}/apply")
def apply(finding_id: str, body: ApplyBody):
    approval_id = (body.id or "").strip()
    if not approval_id:
        raise HTTPException(400, "Approval id is required — approve first via POST /remediation/{finding_id}/approve")
    ap = db.get("remediations", approval_id)
    if not ap or ap.get("finding_id") != finding_id or ap.get("status") != "APPROVED":
        raise HTTPException(400, "Approve first via POST /remediation/{finding_id}/approve")
    result: dict = {"finding_id": finding_id, "approval_id": approval_id,
                    "mode": "SIMULATION", "device_touched": False,
                    "applied_at": store.now()}
    if (body.updated_config_text or "").strip():
        # closed-loop: re-ingest + re-run engines on the fixed config
        from app.services import audit_service
        f = _finding_or_404(finding_id)
        audit = db.get("audits", str(f.get("audit_id", ""))) or {}
        asset = db.get("assets", str(f.get("asset_id", ""))) or {}
        before_fail = 0
        try:
            before = db.find("findings", audit_id=str(f.get("audit_id", "")))
            before_fail = sum(1 for x in before if x.get("status") == "FAIL")
        except Exception:
            before_fail = 0
        record = audit_service.run_audit(
            asset_id=str(f.get("asset_id", "")),
            configuration_id=str(audit.get("configuration_id") or ""),
            config_text=body.updated_config_text,
            frameworks=list(audit.get("frameworks") or ["CIS", "NIST", "STIG", "ISO27001"]),
            asset_criticality=str(asset.get("criticality") or "MEDIUM"),
            detected=audit.get("vendor"))
        same = [x for x in record["findings"] if _same_finding_key(f, x)]
        after_fail = sum(1 for x in record["findings"] if x.get("status") == "FAIL")
        result["re_audit_status"] = same[0]["status"] if same else "UNKNOWN"
        result["verified_fixed"] = result["re_audit_status"] == "PASS"
        result["re_audit_id"] = record["audit_id"]
        result["fail_before"] = before_fail
        result["fail_after"] = after_fail
        result["resolved"] = max(0, before_fail - after_fail)
    else:
        result["re_audit_status"] = "NOT_RUN"
        result["verified_fixed"] = False
        result["note"] = "No candidate config supplied — approval recorded, nothing re-audited."
    db.update("remediations", approval_id, {"status": "APPLIED_SIMULATED"})
    return cfg.ok(result, "Dry-run apply completed (simulation)")
