"""CVE API router: audit-with-CVE, sync, match detail, new-CVE blast radius."""
from __future__ import annotations
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from .kb import VulnKB
from .inventory import extract
from .correlator import correlate, to_findings
from .cbom import build_cbom
from .update import sync_now, assets_affected

router = APIRouter(prefix="/api/v1/okf/cve", tags=["okf-cve"])


def _ok(data: Any, message: str = "ok") -> Dict[str, Any]:
    return {"success": True, "data": data, "message": message}


class CveAuditBody(BaseModel):
    asset_id: str = "ASSET-001"
    vendor: str = "cisco"
    product: str = ""
    version: str = ""
    config_text: str = ""


@router.post("/audit")
def cve_audit(body: CveAuditBody):
    comps = extract(body.config_text, default_vendor=body.vendor, default_product=body.product)
    if body.version and not any(c.get("version") for c in comps):
        comps.append({"vendor": body.vendor, "product": body.product or "unknown",
                      "version": body.version, "component_type": "operating_system",
                      "cpe": None, "source": "explicit"})
    corr = correlate(comps, asset_id=body.asset_id)
    return _ok({"asset_id": body.asset_id, "components": corr["components"],
                "summary": corr["summary"], "matches": corr["matches"],
                "findings": to_findings(corr, body.asset_id),
                "cbom": build_cbom(body.asset_id, corr["components"])})


@router.post("/sync")
def cve_sync(body: Dict[str, Any] = {}):
    return _ok(sync_now(body.get("keyword"), int(body.get("pages", 1)),
                        int(body.get("results_per_page", 20))))


@router.get("/kb")
def kb_info():
    kb = VulnKB().load()
    return _ok({"records": len(kb.records),
                "ids": [r["cve_id"] for r in kb.records][:100]})


class BlastBody(BaseModel):
    cve_id: str
    assets: List[Dict[str, Any]] = []


@router.post("/blast-radius")
def blast_radius(body: BlastBody):
    kb = VulnKB().load()
    rec = next((r for r in kb.records if r["cve_id"] == body.cve_id), None)
    if not rec:
        return {"success": False, "error": {"code": "NOT_FOUND", "message": body.cve_id}}
    return _ok(assets_affected(rec, body.assets))
