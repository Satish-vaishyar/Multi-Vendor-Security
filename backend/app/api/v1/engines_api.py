"""Compliance / CVE(vulnerabilities) / PQC / Analytics(security) read APIs (api.md §13-18)."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional

from app.core import config as cfg
from app.core import persist as db
from app.core import store
from app.services.integration import okf_layer, cve_layer
from app.engines import security as sec_eng

compliance_router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])
vuln_router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])
pqc_router = APIRouter(prefix="/api/v1/pqc", tags=["pqc"])
analytics_router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])


def _audit(audit_id: str) -> dict:
    rec = db.get("audits", audit_id)
    if not rec:
        raise HTTPException(404, "Audit not found")
    return rec


@compliance_router.get("/frameworks")
def frameworks():
    okf = okf_layer()
    return cfg.ok([{"id": f.framework_id, "name": f.name, "version": f.version}
                   for f in okf["fwk"].frameworks.values()])


@compliance_router.get("/{audit_id}")
def compliance_overall(audit_id: str):
    rec = _audit(audit_id)
    return cfg.ok({"audit_id": audit_id, "score": rec["compliance"],
                   "by_framework": rec.get("by_framework", {})})


@compliance_router.get("/{audit_id}/framework/{framework}")
def compliance_framework(audit_id: str, framework: str):
    rec = _audit(audit_id)
    fw = rec.get("by_framework", {}).get(framework.upper(), rec.get("by_framework", {}).get(framework, {}))
    if not fw:
        raise HTTPException(404, f"No data for framework {framework}")
    return cfg.ok({"framework": framework.upper(), "score": fw.get("compliance_score"), "controls": fw})


@compliance_router.get("/{audit_id}/controls")
def compliance_controls(audit_id: str):
    rec = _audit(audit_id)
    items = [{"control_id": f.get("control_id"), "title": f.get("title"),
              "status": f.get("status"), "severity": f.get("severity"),
              "evidence": f.get("evidence")}
             for f in rec["findings"] if f.get("engine") == "compliance"]
    return cfg.ok({"audit_id": audit_id, "items": items})


@vuln_router.get("/cves")
def cve_db(cve_id: Optional[str] = None, vendor: Optional[str] = None,
           product: Optional[str] = None, severity: Optional[str] = None):
    kb = cve_layer()["kb"]().load()
    items = kb.records
    if cve_id:
        items = [r for r in items if r.get("cve_id") == cve_id]
    if vendor:
        items = [r for r in items if vendor.lower() in str(r).lower()]
    if product:
        items = [r for r in items if product.lower() in str(r).lower()]
    if severity:
        items = [r for r in items if str((r.get("cvss") or {}).get("severity", "")).upper() == severity.upper()]
    return cfg.ok({"total": len(items), "items": items[:200]})


@vuln_router.post("/sync")
def cve_sync(body: dict):
    job_id = store.nid("CVE-SYNC")
    db.save("jobs", {"job_id": job_id, "kind": "cve_sync", "status": "RUNNING",
                     "created_at": store.now()})
    try:
        data = cve_layer()["sync_now"](body.get("keyword"),
                                        int(body.get("pages", 1)),
                                        int(body.get("results_per_page", 20)))
        job = db.update("jobs", job_id, {"status": "COMPLETED", "result": data})
    except Exception as e:
        job = db.update("jobs", job_id, {"status": "FAILED", "error": str(e)})
    assert job is not None
    return cfg.ok({"job_id": job_id, "status": job["status"]})


@vuln_router.get("/sync/{job_id}")
def cve_sync_status(job_id: str):
    job = db.get("jobs", job_id)
    if not job or job.get("kind") != "cve_sync":
        raise HTTPException(404, "Sync job not found")
    return cfg.ok(job)


class BlastBody(BaseModel):
    cve_id: str
    assets: list = []


@vuln_router.post("/blast-radius")
def blast_radius(body: BlastBody):
    """New CVE → which assets are affected (cve_okf §23)."""
    kb = cve_layer()["kb"]().load()
    rec = next((r for r in kb.records if r.get("cve_id") == body.cve_id), None)
    if not rec:
        raise HTTPException(404, f"CVE {body.cve_id} not in local KB")
    return cfg.ok(cve_layer()["assets_affected"](rec, body.assets))


@vuln_router.get("/{audit_id}")
def vulns_for_audit(audit_id: str):
    rec = _audit(audit_id)
    matches = rec["cve"]["matches"]
    # Correlate raw CVE matches with unified findings so the UI can link
    # each row to its finding detail (severity + finding_id live there).
    try:
        rows = db.find("findings", audit_id=audit_id, engine="cve")
    except Exception:
        rows = []
    by_key = {}
    for f in rows:
        src = f.get("source") or {}
        ev = f.get("evidence") or {}
        by_key[(src.get("cve"), ev.get("observed"))] = f.get("finding_id")
    items = []
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for m in matches:
        m = dict(m)
        s = str((m.get("cvss") or {}).get("severity") or "UNKNOWN").upper()
        m["severity"] = s
        m["finding_id"] = by_key.get((m.get("cve_id"), m.get("installed_version")))
        items.append(m)
        if s.lower() in sev:
            sev[s.lower()] += 1
    return cfg.ok({"audit_id": audit_id, "summary": {"total": len(items), **sev}, "items": items})


@vuln_router.get("/{audit_id}/{finding_id}")
def vuln_detail(audit_id: str, finding_id: str):
    f = db.get("findings", finding_id)
    if not f or f.get("audit_id") != audit_id:
        raise HTTPException(404, "Finding not found")
    return cfg.ok(f)


@pqc_router.get("/{audit_id}")
def pqc_for_audit(audit_id: str):
    rec = _audit(audit_id)
    p = rec["pqc"]
    return cfg.ok({"audit_id": audit_id, "readiness_score": p.get("readiness_score"),
                   "algorithms": p.get("algorithms", []),
                   "weak_algorithms": [a for a in p.get("algorithms", []) if a.get("pqc_status") == "MIGRATION_REQUIRED"],
                   "migration_recommendations": p.get("migration_recommendations", [])})


@analytics_router.get("/{audit_id}")
def analytics_for_audit(audit_id: str):
    rec = _audit(audit_id)
    s = rec["security"]
    return cfg.ok({"audit_id": audit_id, "risk_score": s.get("risk_score"),
                   "anomalies": s.get("anomalies", []), "patterns": s.get("patterns", [])})


class FleetBody(BaseModel):
    asset_ids: List[str] = []


@analytics_router.post("/fleet")
def fleet_start(body: FleetBody):
    """Fleet outlier detection: latest Canonical IR per asset → M7 (fit per fleet)."""
    from app.services.integration import m7_fit_fleet, okf_flat_to_m7
    job_id = store.nid("FLEET")
    latest: dict = {}
    for a in db.find("audits"):
        aid = a.get("asset_id")
        if aid in body.asset_ids and (aid not in latest or a.get("created_at", 0) > latest[aid].get("created_at", 0)):
            latest[aid] = a
    aids = [aid for aid in body.asset_ids if aid in latest]
    feats = [okf_flat_to_m7(latest[aid].get("flat_ir", {})) for aid in aids]
    m7 = m7_fit_fleet(feats) if feats else {"method": "none", "outliers": [], "labels": []}
    devices = [{"asset_id": aid, "outlier": bool(m7["outliers"][i]) if i < len(m7["outliers"]) else False,
                "cluster": (m7.get("labels") or [0])[i] if i < len(m7.get("labels") or []) else 0}
               for i, aid in enumerate(aids)]
    db.save("jobs", {"job_id": job_id, "kind": "fleet", "status": "COMPLETED",
                     "method": m7.get("method"), "assets": len(aids),
                     "outliers": sum(1 for d in devices if d["outlier"]),
                     "devices": devices, "created_at": store.now()})
    return cfg.ok({"job_id": job_id, "status": "COMPLETED"})


@analytics_router.get("/fleet/{job_id}")
def fleet_status(job_id: str):
    job = db.get("jobs", job_id)
    if not job or job.get("kind") != "fleet":
        raise HTTPException(404, "Fleet job not found")
    return cfg.ok(job)
