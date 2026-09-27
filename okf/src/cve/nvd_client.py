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
                start = m.get("versionStartIncluding") or m.get("versionStartExcluding")
                end = m.get("versionEndIncluding") or m.get("versionEndExcluding")
                if not start and not end:
                    # No range bounds: the criteria names one exact vulnerable
                    # version (e.g. ...:ios:12.0(32)S12:...). Without this the
                    # entry is unbounded and would match EVERY installed
                    # version as VULNERABLE. A '*'/'-' criteria version means
                    # all versions and stays unbounded.
                    ver = parts["version"]
                    if ver not in ("*", "-", "", None):
                        start = end = ver
                affected.append({
                    "vendor": parts["vendor"], "product": parts["product"],
                    "cpe": m.get("criteria", ""),
                    "affected_versions": [{
                        "start": start,
                        "start_inclusive": True if (m.get("versionStartIncluding") or
                                                   (not m.get("versionStartExcluding") and start)) else False,
                        "end": end,
                        "end_inclusive": True if (m.get("versionEndIncluding") or
                                                 (not m.get("versionEndExcluding") and end)) else False,
                    }]})
    return {"cve_id": cve_id, "description": desc[:2000],
            "published": (cve.get("published", "") or "")[:10],
            "last_modified": (cve.get("lastModified", "") or "")[:10],
            "source": "NVD", "cvss": cvss, "cwe": [c for c in cwe if c],
            "references": refs, "affected": affected}


def sync(keyword: Optional[str] = None, pages: int = 1,
         results_per_page: int = 20, *, keywords: Optional[List[str]] = None,
         drop_seeds: bool = False, delay: Optional[float] = None) -> Dict[str, Any]:
    """Fetch pages from NVD and upsert. Returns counts. Raises on network error.

    Speed design (NVD caps keyless callers at ~5 req/30s, keyed at ~50/30s):
    - few big pages beat many small ones (results_per_page up to 2000);
    - one shared pacing delay between requests keeps us under the limit;
    - upserts defer the KB reindex until the single save() at the end.
    """
    import time as _time
    from .kb import VulnKB
    queries = [k for k in (keywords or []) if k] or [keyword]
    rpp = max(1, min(int(results_per_page or 20), 2000))
    pages = max(1, int(pages or 1))
    key = os.getenv("NVD_API_KEY", "").strip()
    if delay is None:
        delay = 0.0 if len(queries) * pages <= 1 else (0.7 if key else 6.5)
    kb = VulnKB().load()
    added = updated = 0
    seen_before = {r.get("cve_id") for r in kb.records}
    first = True
    for q in queries:
        for p in range(pages):
            if not first and delay:
                _time.sleep(delay)
            first = False
            payload = fetch_cves(rpp, p * rpp, q)
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
    dropped = kb.drop_seeds() if drop_seeds else 0
    kb.save()
    return {"added": added, "updated": updated, "dropped_seeds": dropped,
            "total": len(kb.records)}
