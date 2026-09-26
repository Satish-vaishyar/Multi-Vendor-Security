"""Scrape NIST SP 800-53 Rev.5 OSCAL catalog (real, machine-readable) into OKF frameworks.

Source: GSA OSCAL content mirror of NIST content:
  https://raw.githubusercontent.com/GSA/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json
Fallback: usnistgov/oscal-content. Result: knowledge/frameworks/NIST_OSCAL.json + control count report.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path
import httpx

URLS = [
    "https://raw.githubusercontent.com/GSA/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
]
OUT = Path(__file__).parent.parent / "knowledge" / "frameworks" / "NIST_OSCAL.json"


def scrape(timeout: float = 60.0) -> dict:
    last_err = ""
    for url in URLS:
        try:
            r = httpx.get(url, timeout=timeout, follow_redirects=True)
            if r.status_code == 200:
                cat = r.json().get("catalog", {})
                groups = cat.get("groups", []) or []
                direct = cat.get("controls", []) or []
                flat = []

                def walk(cs):
                    for c in cs:
                        flat.append({"id": c.get("id"), "title": c.get("title"),
                                     "parts": len(c.get("parts", []))})
                        if c.get("controls"):
                            walk(c["controls"])
                        if c.get("parts"):
                            pass
                walk(direct)
                for g in groups:
                    walk(g.get("controls", []))
                OUT.write_text(json.dumps({"source_url": url, "families": len(groups),
                                           "total_controls": len(flat), "controls": flat[:2000]},
                                          indent=2), encoding="utf-8")
                return {"ok": True, "source": url, "families": len(groups),
                        "total_controls": len(flat), "out": str(OUT)}
            last_err = f"HTTP {r.status_code}"
        except Exception as e:
            last_err = str(e)
    return {"ok": False, "error": last_err}


if __name__ == "__main__":
    print(json.dumps(scrape(), indent=2))
