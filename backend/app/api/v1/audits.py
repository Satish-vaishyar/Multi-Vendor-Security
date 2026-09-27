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
    rows = db.select("audits", ["audit_id", "status", "progress", "stages"], limit=1, audit_id=audit_id)
    if not rows:
        raise HTTPException(404, "Audit not found")
    rec = rows[0]
    return cfg.ok({"audit_id": audit_id, "status": rec["status"], "progress": rec.get("progress", 100),
                   "stages": rec.get("stages", {})})


@router.get("/{audit_id}/summary")
def get_summary(audit_id: str):
    """Lightweight audit overview for pickers/dashboards.

    Same brief as results but WITHOUT the heavy findings + canonical_ir
    payloads — a single audit row plus GROUP BY counts on findings.
    """
    rows = db.select("audits", ["audit_id", "status", "progress", "summary",
                                "by_framework", "cve"], limit=1, audit_id=audit_id)
    if not rows:
        raise HTTPException(404, "Audit not found")
    rec = rows[0]
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
    """Full structured result for the Results page (manager + developer view).

    Returns the complete picture in one call so the UI never renders blanks:
    executive summary, per-framework scores (with pass/total), CVE/PQC/security
    rollups, finding distributions, provenance metadata, and the findings list.
    Heavy per-control explanations stay on GET /compliance/{id}/controls,
    per-CVE detail on GET /vulnerabilities/{id}, PQC detail on GET /pqc/{id}.
    """
    rec = db.get("audits", audit_id)
    if not rec:
        raise HTTPException(404, "Audit not found")
    s = rec.get("summary", {}) or {}
    by_fw = rec.get("by_framework", {}) or {}
    cve = rec.get("cve", {}) or {}
    cve_sum = (cve.get("summary", {}) or {})
    pqc = rec.get("pqc", {}) or {}
    sec = rec.get("security", {}) or {}
    findings = rec.get("findings", []) or []

    # Distributions so the UI can render charts without client-side guessing.
    by_engine: dict = {}
    by_severity: dict = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    by_status: dict = {"FAIL": 0, "PASS": 0, "UNKNOWN": 0}
    for f in findings:
        e = str((f.get("engine") or f.get("type") or "UNKNOWN")).upper()
        by_engine[e] = by_engine.get(e, 0) + 1
        sev = str(f.get("severity") or "UNKNOWN").upper()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        st = str(f.get("status") or "UNKNOWN").upper()
        by_status[st] = by_status.get(st, 0) + 1

    frameworks = {}
    for k, v in by_fw.items():
        v = v or {}
        frameworks[k] = {"score": v.get("compliance_score", 0),
                         "compliance_score": v.get("compliance_score", 0),
                         "total": v.get("total", 0), "passed": v.get("passed", 0),
                         "failed": v.get("failed", 0), "unknown": v.get("unknown", 0)}

    return cfg.ok({"audit_id": audit_id,
                   "asset_id": rec.get("asset_id"), "configuration_id": rec.get("configuration_id"),
                   "status": rec.get("status"), "vendor": rec.get("vendor", {}),
                   "summary": {"compliance_score": s.get("compliance_score"),
                               "total": s.get("total", len(findings)),
                               "passed": s.get("passed", 0), "failed": s.get("failed", 0),
                               "unknown": s.get("unknown", 0),
                               "critical": s.get("CRITICAL", 0),
                               "high": s.get("HIGH", 0), "medium": s.get("MEDIUM", 0),
                               "low": s.get("LOW", 0),
                               "security_risk": s.get("security_risk"),
                               "pqc_readiness": s.get("pqc_readiness"),
                               "cve": cve_sum},
                   "config_sha256": rec.get("config_sha256"), "versions": rec.get("versions", {}),
                   "frameworks": frameworks,
                   "cve": {"summary": cve_sum,
                           "vulnerable": cve_sum.get("vulnerable", 0),
                           "not_affected": cve_sum.get("not_affected", 0),
                           "unknown": cve_sum.get("unknown", 0),
                           "total_matches": len(cve.get("matches", []) or []),
                           "unresolved": len(cve.get("unresolved", []) or []),
                           "components": len(cve.get("components", []) or [])},
                   "pqc": {"readiness": pqc.get("readiness_score", pqc.get("readiness", 0)),
                           "readiness_score": pqc.get("readiness_score", pqc.get("readiness", 0)),
                           "readiness_label": pqc.get("readiness_label", ""),
                           "counts": pqc.get("counts", {}),
                           "algorithms_total": len(pqc.get("algorithms", []) or []),
                           "migration_required": len([a for a in (pqc.get("algorithms", []) or [])
                                                      if a.get("pqc_status") == "MIGRATION_REQUIRED"]),
                           "migration_recommendations": pqc.get("migration_recommendations", [])},
                   "security": {"risk_score": sec.get("risk_score"),
                                "anomalies_total": len(sec.get("anomalies", []) or []),
                                "patterns": sec.get("patterns", [])},
                   "counts": {"total_findings": len(findings),
                              "by_engine": by_engine, "by_severity": by_severity,
                              "by_status": by_status},
                   "findings": findings,
                   "unknown_lines": rec.get("unknown_lines", []),
                   "llm_offline": rec.get("llm_offline", True),
                   "ir_validation": rec.get("ir_validation", {}),
                   "canonical_ir": rec.get("canonical_ir", {})})


@router.get("/{audit_id}/evidence")
def get_evidence(audit_id: str):
    # Projected reads: provenance slice + compliance findings only (no full payloads).
    rows = db.select("audits", ["configuration_id", "data->'provenance' AS provenance"],
                     limit=1, audit_id=audit_id)
    if not rows:
        raise HTTPException(404, "Audit not found")
    rec = rows[0]
    prov = rec.get("provenance", {}) or {}
    items = []
    for f in db.select("findings", ["control_id", "evidence"], limit=1000,
                       audit_id=audit_id, engine="compliance"):
        ev = f.get("evidence", {}) if isinstance(f.get("evidence"), dict) else {}
        prop = ev.get("property", "")
        src = prov.get(prop, {})
        items.append({"control_id": f.get("control_id"), "property": prop,
                      "observed_value": ev.get("observed_value"), "expected_value": ev.get("expected_value"),
                      "source": {"configuration_id": rec.get("configuration_id"),
                                 "line": src.get("line", ""), "line_no": src.get("line_no")}})

    return cfg.ok({"audit_id": audit_id, "items": items})
