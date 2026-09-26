"""CVE update pipeline + 'new CVE affects my infrastructure' (cve_okf §22-23).

- sync_now(): NVD → local KB (delegates to nvd_client.sync, offline-safe).
- assets_affected(cve_record, assets): given a CVE record and an asset inventory
  [{asset_id, vendor, product, version}], return per-asset VULNERABLE/NOT_AFFECTED.
"""
from __future__ import annotations
from typing import Any, Dict, List
from .version_range import match_record


def sync_now(keyword: str | None = None, pages: int = 1,
             results_per_page: int = 20) -> Dict[str, Any]:
    try:
        from .nvd_client import sync
        return {"ok": True, **sync(keyword, pages, results_per_page)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def assets_affected(cve_record: Dict[str, Any],
                    assets: List[Dict[str, Any]]) -> Dict[str, Any]:
    rows = []
    for a in assets:
        per_product = [aff for aff in cve_record.get("affected", [])
                       if (aff.get("vendor", "").lower(), aff.get("product", "").lower()) ==
                       ((a.get("vendor") or "").lower(), (a.get("product") or "").lower())]
        if not per_product or not a.get("version"):
            rows.append({**a, "status": "UNKNOWN"})
            continue
        vuln = any(match_record(a["version"], aff.get("affected_versions", []))["affected"]
                   for aff in per_product)
        rows.append({**a, "status": "VULNERABLE" if vuln else "NOT_AFFECTED"})
    return {"cve_id": cve_record.get("cve_id"),
            "assets": rows,
            "vulnerable": [r for r in rows if r["status"] == "VULNERABLE"]}
