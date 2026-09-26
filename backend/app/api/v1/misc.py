"""Dashboard summary, OKF browser, vendor detection (api.md §29-30, §32)."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.core import config as cfg
from app.core import persist as db
from app.parsers import vendor_detector, canonical as canon
from app.services.integration import okf_layer

dashboard_router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])
okf_router = APIRouter(prefix="/api/v1/okf", tags=["okf"])
detect_router = APIRouter(prefix="/api/v1/detection", tags=["detection"])


@dashboard_router.get("/summary")
def summary():
    assets = db.find("assets")
    live = [a for a in assets if a.get("status") == "ACTIVE"]
    findings = db.find("findings")
    # per-asset risk from real FAIL findings (CRITICAL/HIGH -> at risk)
    risky = {f.get("asset_id") for f in findings
             if f.get("status") == "FAIL"
             and str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")}
    at_risk_ids = {a.get("asset_id") for a in live} & risky
    def cnt(sev: str):
        return sum(1 for f in findings if str(f.get("severity", "")).upper() == sev and f.get("status") == "FAIL")
    cve_crit = sum(1 for f in findings if f.get("engine") == "cve" and f.get("severity") == "CRITICAL")
    audits = db.find("audits")
    scored = [a for a in audits if (a.get("summary") or {}).get("compliance_score") is not None]
    overall = round(sum(a["summary"]["compliance_score"] for a in scored) / len(scored), 1) if scored else 0.0
    # Aggregate per-framework scores from audits (each audit stores by_framework->{fw:{compliance_score}})
    # Frontend Dashboard.tsx reads d.frameworks for the "Compliance by Framework" bar chart.
    fw_sums: dict[str, float] = {}
    fw_counts: dict[str, int] = {}
    for a in audits:
        by_fw = a.get("by_framework") or {}
        for fw, v in by_fw.items():
            try:
                s = float((v or {}).get("compliance_score", 0))
            except (TypeError, ValueError):
                continue
            fw_sums[fw] = fw_sums.get(fw, 0.0) + s
            fw_counts[fw] = fw_counts.get(fw, 0) + 1
    frameworks = {fw: {"score": round(fw_sums[fw] / fw_counts[fw], 1)} for fw in fw_sums}
    # PQC readiness averaged across audits that ran the PQC engine
    readiness = [a["pqc"]["readiness_score"] for a in audits
                 if isinstance(a.get("pqc"), dict) and a["pqc"].get("readiness_score") is not None]
    pqc_avg = round(sum(readiness) / len(readiness), 1) if readiness else 0.0
    return cfg.ok({"assets": {"total": len(live), "healthy": len(live) - len(at_risk_ids),
                              "at_risk": len(at_risk_ids)},
                   "compliance": {"overall": overall},
                   "frameworks": frameworks,
                   "findings": {"critical": cnt("CRITICAL"), "high": cnt("HIGH"),
                                "medium": cnt("MEDIUM"), "low": cnt("LOW")},
                   "cve": {"critical": cve_crit,
                           "high": sum(1 for f in findings if f.get("engine") == "cve" and f.get("severity") == "HIGH")},
                   "pqc": {"audits": len(audits), "readiness": pqc_avg},
                   "training": {"pending": len(db.find("training", status="PENDING"))}})


@okf_router.get("/properties")
def okf_properties(category: Optional[str] = None):
    okf = okf_layer()
    items = okf["props"].all()
    if category:
        items = [p for p in items if p.category == category]
    return cfg.ok([p.model_dump() for p in items])


@okf_router.get("/controls")
def okf_controls(framework: Optional[str] = None, category: Optional[str] = None, severity: Optional[str] = None):
    okf = okf_layer()
    items = okf["ckb"].all()
    if framework:
        items = [c for c in items if framework.upper() in (str(k).upper() for k in (c.frameworks or {}))]
    if category:
        items = [c for c in items if c.category == category]
    if severity:
        items = [c for c in items if c.severity == severity.upper()]
    return cfg.ok([c.model_dump() for c in items])


@okf_router.get("/controls/{control_id}")
def okf_control(control_id: str):
    okf = okf_layer()
    c = okf["ckb"].controls.get(control_id)
    if not c:
        raise HTTPException(404, f"Control {control_id} not found")
    d = c.model_dump()
    d["remediation"] = okf["rem"].index.get(control_id, {})
    return cfg.ok(d)


@okf_router.get("/crosswalk/{control_id}")
def okf_crosswalk(control_id: str):
    okf = okf_layer()
    return cfg.ok(okf["xwalk"].for_control(control_id, okf["ckb"].controls))


class DetectBody(BaseModel):
    configuration_id: str = ""
    config_text: str = ""


@detect_router.post("/vendor")
def detect(body: DetectBody):
    text = body.config_text
    if body.configuration_id:
        rec = db.get("configurations", body.configuration_id)
        if rec:
            text = rec["config_text"]
    if not text:
        raise HTTPException(400, "Provide configuration_id or config_text")
    return cfg.ok(vendor_detector.detect_vendor(text))
