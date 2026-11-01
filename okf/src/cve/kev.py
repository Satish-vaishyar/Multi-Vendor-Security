"""CISA Known Exploited Vulnerabilities (KEV) enrichment.

``sync_kev()`` downloads the public KEV catalogue and flags matching KB records ``exploited=True``
(+ ``kev_added`` / ``kev_due``). Records not in the catalogue keep whatever NVD supplied. Offline-safe: the
caller gets ``{"ok": False, "error": ...}`` instead of an exception.
"""
from __future__ import annotations
import os
from typing import Any, Dict, Iterable

KEV_URL = os.getenv("KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")


def apply_kev(records: Iterable[Dict[str, Any]], catalogue: Dict[str, Any]) -> int:
    """Flag records present in ``catalogue`` ({"vulnerabilities": [{cveID, dateAdded, dueDate}]}). Returns count flagged."""
    by_id = {v.get("cveID"): v for v in catalogue.get("vulnerabilities", []) if v.get("cveID")}
    n = 0
    for r in records:
        v = by_id.get(r.get("cve_id"))
        if v:
            r["exploited"] = True
            r["kev_added"], r["kev_due"] = v.get("dateAdded", ""), v.get("dueDate", "")
            n += 1
    return n


def sync_kev(timeout: float = 60.0) -> Dict[str, Any]:
    try:
        import httpx
        from .kb import VulnKB
        r = httpx.get(KEV_URL, timeout=timeout, headers={"User-Agent": "OKF-SIHAuditor/1.0"})
        r.raise_for_status()
        cat = r.json()
        kb = VulnKB().load()
        flagged = apply_kev(kb.records, cat)
        kb.save()
        return {"ok": True, "kev_total": len(cat.get("vulnerabilities", [])), "flagged_in_kb": flagged}
    except Exception as e:                                # noqa: BLE001
        return {"ok": False, "error": str(e)}
