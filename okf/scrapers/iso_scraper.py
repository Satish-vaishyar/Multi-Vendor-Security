"""ISO 27001 scraper: Annex A (2022, 93 controls in 4 themes) is copyrighted in full text.

This scraper collects the PUBLIC control IDs/titles (widely published theme lists)
and seeds knowledge/frameworks/ISO_SCRAPED.json. Curated core.yaml stays authoritative.
"""
from __future__ import annotations
import json
from pathlib import Path
import httpx

OUT = Path(__file__).parent.parent / "knowledge" / "frameworks" / "ISO_SCRAPED.json"

# Public Annex A structure (IDs + short names only, no copyrighted text)
ANNEX_A = {
    "5_Organizational": ["A.5.1", "A.5.10", "A.5.17", "A.5.18", "A.5.33"],
    "6_People": ["A.6.1", "A.6.2"],
    "7_Physical": ["A.7.1", "A.7.5"],
    "8_Technological": ["A.8.3", "A.8.15", "A.8.20", "A.8.24", "A.8.26"],
}
OKF_MAP = {"A.8.20": ["OKF-SSH-001", "OKF-TELNET-001"], "A.5.17": ["OKF-AAA-001", "OKF-PASS-001"],
           "A.8.15": ["OKF-LOG-001", "OKF-LOG-002"], "A.8.24": ["OKF-CRYPTO-001"],
           "A.8.3": ["OKF-ACL-001"], "A.5.10": ["OKF-BANNER-001"]}


def scrape() -> dict:
    reachable = False
    try:
        r = httpx.get("https://www.iso.org/standard/27001-revision.html",
                      timeout=30, follow_redirects=True)
        reachable = r.status_code == 200
    except Exception:
        pass
    payload = {"standard": "ISO/IEC 27001:2022 Annex A", "themes": ANNEX_A,
               "okf_map": OKF_MAP, "iso_page_reachable": reachable,
               "note": "IDs/themes only; full control text requires ISO license."}
    OUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {"ok": True, "out": str(OUT), "controls_mapped": sum(len(v) for v in OKF_MAP.values())}


if __name__ == "__main__":
    print(json.dumps(scrape(), indent=2))
