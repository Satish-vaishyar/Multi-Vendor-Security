"""Audits: POST /audits, GET /audits/{id}, GET /audits/{id}/results, GET /audits/{id}/evidence (api.md §10-12, §31)."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional

from app.core import config as cfg
from app.core import persist as db
from app.services import audit_service

router = APIRouter(prefix="/api/v1/audits", tags=["audits"])


class AuditBody(BaseModel):
    asset_id: str = "AST-001"
    configuration_id: str = ""
    frameworks: List[str] = ["CIS", "NIST", "STIG", "ISO27001"]
    run_cve: bool = True
    run_pqc: bool = True
    run_security_analysis: bool = True
    generate_report: bool = False


@router.get("")
def list_audits():
    """Lightweight audit list for pickers/dashboards.

    One projected audit query plus one GROUP BY over findings — no per-audit
    fan-out, no findings/canonical_ir payloads.
    """
    rows = db.select("audits", ["audit_id", "status", "progress", "summary",
                                "by_framework", "cve", "asset_id", "configuration_id"])
    groups = db.count_by("findings", ["audit_id", "engine", "severity"])
    eng: dict = {}
    for g in groups:
        aid = g.get("audit_id")
        e = str(g.get("engine", "") or "UNKNOWN").upper()
        sev = str(g.get("severity", "") or "UNKNOWN").upper()
        eng.setdefault(aid, {}).setdefault(e, {})[sev] = int(g.get("n", 0))
    items = []
    for r in rows:
        s = r.get("summary", {}) or {}
        by_fw = r.get("by_framework", {}) or {}
        cve = (r.get("cve", {}) or {}).get("summary", {}) or {}
        items.append({"audit_id": r.get("audit_id"), "asset_id": r.get("asset_id"),
                      "configuration_id": r.get("configuration_id"),
                      "status": r.get("status"), "progress": r.get("progress", 100),
                      "summary": {"compliance_score": s.get("compliance_score"),
                                  "critical": s.get("CRITICAL", 0), "high": s.get("HIGH", 0),
                                  "medium": s.get("MEDIUM", 0), "low": s.get("LOW", 0),
                                  "security_risk": s.get("security_risk"),
                                  "pqc_readiness": s.get("pqc_readiness")},
                      "frameworks": {k: {"score": v.get("compliance_score", 0)}
                                     for k, v in by_fw.items()},
                      "cve": {"vulnerable": cve.get("vulnerable", 0),
                              "not_affected": cve.get("not_affected", 0),
                              "unknown": cve.get("unknown", 0)},
                      "engines": {e: {sev: n for sev, n in sevs.items()}
                                  for e, sevs in eng.get(r.get("audit_id"), {}).items()}})
    return cfg.ok({"items": items, "total": len(items)})


@router.post("")
def create_audit(body: AuditBody):
    rec = db.get("configurations", body.configuration_id)
    if not rec:
        raise HTTPException(404, "Configuration not found — upload first via POST /configurations/upload")
    asset = db.get("assets", body.asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found — create it first via POST /assets")
    record = audit_service.run_audit(
        asset_id=body.asset_id, configuration_id=body.configuration_id,
        config_text=rec["config_text"], frameworks=body.frameworks,
        run_cve=body.run_cve, run_pqc=body.run_pqc,
        run_security=body.run_security_analysis,
        asset_criticality=str(asset.get("criticality") or "MEDIUM"),
        detected=rec.get("detection"))
    return cfg.ok({"audit_id": record["audit_id"], "status": record["status"]}, "Audit completed")


@router.get("/{audit_id}")
def get_audit(audit_id: str):
    rec = db.get("audits", audit_id)
    if not rec:
        raise HTTPException(404, "Audit not found")
    return cfg.ok({"audit_id": audit_id, "status": rec["status"], "progress": rec.get("progress", 100),
                   "stages": rec.get("stages", {})})


@router.get("/{audit_id}/summary")
def get_summary(audit_id: str):
    """Lightweight audit overview for pickers/dashboards.

    Same brief as results but WITHOUT the heavy findings + canonical_ir
    payloads — a single audit row plus GROUP BY counts on findings.
    """
    rec = db.get("audits", audit_id, inflate=False)
    if not rec:
        raise HTTPException(404, "Audit not found")
    s = rec.get("summary", {}) or {}
    groups = db.count_by("findings", ["engine", "severity"], audit_id=audit_id)
    engines: dict = {}
    engine_sev: dict = {}
    for g in groups:
        e = str(g.get("engine", "") or "UNKNOWN").upper()
        sev = str(g.get("severity", "") or "UNKNOWN").upper()
        engines[e] = engines.get(e, 0) + int(g.get("n", 0))
        engine_sev.setdefault(e, {})[sev] = int(g.get("n", 0))
    return cfg.ok({"audit_id": audit_id, "status": rec.get("status"),
                   "progress": rec.get("progress", 100),
                   "summary": {"compliance_score": s.get("compliance_score"),
                               "critical": s.get("CRITICAL", 0), "high": s.get("HIGH", 0),
                               "medium": s.get("MEDIUM", 0), "low": s.get("LOW", 0),
                               "security_risk": s.get("security_risk"),
                               "pqc_readiness": s.get("pqc_readiness")},
                   "frameworks": {k: {"score": v.get("compliance_score", 0)}
                                  for k, v in (rec.get("by_framework", {}) or {}).items()},
                   "cve": {"vulnerable": ((rec.get("cve", {}) or {}).get("summary", {}) or {}).get("vulnerable", 0),
                           "not_affected": ((rec.get("cve", {}) or {}).get("summary", {}) or {}).get("not_affected", 0),
                           "unknown": ((rec.get("cve", {}) or {}).get("summary", {}) or {}).get("unknown", 0)},
                   "engines": engines, "engine_sev": engine_sev})


@router.get("/{audit_id}/results")
def get_results(audit_id: str):
    rec = db.get("audits", audit_id)
    if not rec:
        raise HTTPException(404, "Audit not found")
    s = rec["summary"]
    return cfg.ok({"audit_id": audit_id,
                   "summary": {"compliance_score": s.get("compliance_score"), "critical": s.get("CRITICAL", 0),
                               "high": s.get("HIGH", 0), "medium": s.get("MEDIUM", 0), "low": s.get("LOW", 0)},
                   "config_sha256": rec.get("config_sha256"), "versions": rec.get("versions", {}),
                   "frameworks": {k: {"score": v.get("compliance_score", 0)} for k, v in rec.get("by_framework", {}).items()},
                   "cve": {"vulnerable": rec["cve"]["summary"].get("vulnerable", 0),
                           "not_affected": rec["cve"]["summary"].get("not_affected", 0),
                           "unknown": rec["cve"]["summary"].get("unknown", 0)},
                   "pqc": {"readiness": rec["pqc"].get("readiness_score", 0)},
                   "findings": rec["findings"],
                   "ir_validation": rec.get("ir_validation", {}),
                   "canonical_ir": rec.get("canonical_ir", {})})


@router.get("/{audit_id}/evidence")
def get_evidence(audit_id: str):
    rec = db.get("audits", audit_id)
    if not rec:
        raise HTTPException(404, "Audit not found")
    items = []
    prov = rec.get("provenance", {})
    for f in rec.get("findings", []):
        if f.get("engine") != "compliance":
            continue
        ev = f.get("evidence", {}) if isinstance(f.get("evidence"), dict) else {}
        prop = ev.get("property", "")
        src = prov.get(prop, {})
        items.append({"control_id": f.get("control_id"), "property": prop,
                      "observed_value": ev.get("observed_value"), "expected_value": ev.get("expected_value"),
                      "source": {"configuration_id": rec.get("configuration_id"),
                                 "line": src.get("line", ""), "line_no": src.get("line_no")}})

    return cfg.ok({"audit_id": audit_id, "items": items})
