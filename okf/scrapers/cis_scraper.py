"""CIS scraper: CIS Benchmarks are paywalled; scrape only PUBLIC control summaries.

Fetches the public CIS Benchmarks index + CIS Controls v8 page, extracts control
titles, and writes knowledge/frameworks/CIS_SCRAPED.json. Curated core.yaml stays
authoritative (docs okf.md §34: official source > expert rule > AI).
"""
from __future__ import annotations
import json
import re
from pathlib import Path
import httpx

URLS = [
    "https://www.cisecurity.org/controls/v8",
    "https://www.cisecurity.org/cis-benchmarks",
]
OUT = Path(__file__).parent.parent / "knowledge" / "frameworks" / "CIS_SCRAPED.json"


def scrape(timeout: float = 45.0) -> dict:
    found: list[str] = []
    for url in URLS:
        try:
            r = httpx.get(url, timeout=timeout, follow_redirects=True,
                          headers={"User-Agent": "OKF-research/1.0"})
            if r.status_code == 200:
                titles = re.findall(r"CIS Control \d+[^<]{0,120}", r.text)
                found.extend(titles[:50])
        except Exception as e:
            found.append(f"ERR {url}: {e}")
    OUT.write_text(json.dumps({"sources": URLS, "extracts": found[:100],
                               "note": "Public summaries only; full benchmarks require license. Curated controls remain authoritative."},
                              indent=2), encoding="utf-8")
    return {"ok": True, "extracts": len(found), "out": str(OUT)}


if __name__ == "__main__":
    print(json.dumps(scrape(), indent=2))
