"""NVD API 2.0 client (cve_okf §13): fetch → normalize → upsert into VulnKB.

Endpoints: https://services.nvd.nist.gov/rest/json/cves/2.0 (CVE) and
cpe/2.0 + cpe-match/2.0 (dictionary/match criteria). Optional NVD_API_KEY
env raises rate limit. Small-page fetches for SIH demo; offline-safe.
"""
from __future__ import annotations
import os
import re
from typing import Any, Dict, List, Optional

BASE = "https://services.nvd.nist.gov/rest/json"


def _headers() -> Dict[str, str]:
    h = {"User-Agent": "OKF-SIHAuditor/1.0"}
    k = os.getenv("NVD_API_KEY", "").strip()
    if k:
        h["apiKey"] = k
    return h


def fetch_cves(results_per_page: int = 20, start_index: int = 0,
               keyword: Optional[str] = None, timeout: float = 60.0) -> Dict[str, Any]:
    import httpx
    params: Dict[str, Any] = {"resultsPerPage": results_per_page, "startIndex": start_index}
    if keyword:
        params["keywordSearch"] = keyword

    def _get(headers: Dict[str, str]) -> Dict[str, Any]:
        r = httpx.get(f"{BASE}/cves/2.0", params=params, headers=headers, timeout=timeout)
        r.raise_for_status()
        return r.json()

    key = os.getenv("NVD_API_KEY", "").strip()
    try:
        return _get(_headers())
    except Exception as e:
        status = getattr(getattr(e, "response", None), "status_code", None)
        if key and status in (401, 403, 404):
            # Provided key rejected (invalid/expired) — retry anonymously rather
            # than failing the whole sync; NVD allows low-rate keyless access.
            return _get({"User-Agent": "OKF-SIHAuditor/1.0"})
        raise


def _cpe_to_parts(cpe: str) -> Dict[str, str]:
    p = cpe.split(":")
    # cpe:2.3:part:vendor:product:version:...
    try:
        return {"part": p[2], "vendor": p[3], "product": p[4], "version": p[5]}
    except IndexError:
        return {"part": "o", "vendor": "*", "product": "*", "version": "*"}


def normalize_nvd_item(item: Dict[str, Any]) -> Dict[str, Any]:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    desc = next((d.get("value", "") for d in cve.get("descriptions", [])
                 if d.get("lang") == "en"), "")
    metrics = cve.get("metrics", {})
    cvss: Dict[str, Any] = {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m0 = metrics[key][0]
            d = m0.get("cvssData", {})
            cvss = {"version": d.get("version", ""), "base_score": d.get("baseScore"),
                    "severity": (m0.get("baseSeverity") or d.get("baseSeverity") or "").upper(),
                    "vector": d.get("vectorString", "")}
            break
    cwe = [w.get("description", [{}])[0].get("value", "")
           for w in cve.get("weaknesses", []) if w.get("description")]
    refs = [{"url": r.get("url", ""), "tags": r.get("tags", [])}
            for r in cve.get("references", [])]
    affected = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable", False):
                    continue
                parts = _cpe_to_parts(m.get("criteria", ""))
                affected.append({
                    "vendor": parts["vendor"], "product": parts["product"],
                    "cpe": m.get("criteria", ""),
                    "affected_versions": [{
                        "start": m.get("versionStartIncluding") or m.get("versionStartExcluding"),
                        "start_inclusive": "versionStartIncluding" in m,
                        "end": m.get("versionEndIncluding") or m.get("versionEndExcluding"),
                        "end_inclusive": "versionEndIncluding" in m,
                    }]})
    return {"cve_id": cve_id, "description": desc[:2000],
            "published": (cve.get("published", "") or "")[:10],
            "last_modified": (cve.get("lastModified", "") or "")[:10],
            "source": "NVD", "cvss": cvss, "cwe": [c for c in cwe if c],
            "references": refs, "affected": affected}


def sync(keyword: Optional[str] = None, pages: int = 1,
         results_per_page: int = 20) -> Dict[str, Any]:
    """Fetch pages from NVD and upsert. Returns counts. Raises on network error."""
    from .kb import VulnKB
    kb = VulnKB().load()
    added = updated = 0
    seen_before = {r.get("cve_id") for r in kb.records}
    for p in range(pages):
        payload = fetch_cves(results_per_page, p * results_per_page, keyword)
        for item in payload.get("vulnerabilities", []):
            rec = normalize_nvd_item(item)
            if not rec["cve_id"]:
                continue
            kb.upsert(rec)
            if rec["cve_id"] in seen_before:
                updated += 1
            else:
                added += 1
                seen_before.add(rec["cve_id"])
    kb.save()
    return {"added": added, "updated": updated, "total": len(kb.records)}
