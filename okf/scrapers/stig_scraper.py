"""DISA STIG scraper: parses public STIG library index + supports local XCCDF import.

- Scrapes https://public.cyber.mil/stigs/ for network-device STIG titles.
- import_xccdf(path): parse a downloaded STIG XCCDF XML (e.g. Cisco_IOS_XE_NDM_STIG) into OKF control rows.
Writes knowledge/frameworks/STIG_SCRAPED.json.
"""
from __future__ import annotations
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
import httpx

OUT = Path(__file__).parent.parent / "knowledge" / "frameworks" / "STIG_SCRAPED.json"
INDEX = "https://public.cyber.mil/stigs/"


def scrape(timeout: float = 45.0) -> dict:
    titles: list[str] = []
    try:
        r = httpx.get(INDEX, timeout=timeout, follow_redirects=True,
                      headers={"User-Agent": "OKF-research/1.0"})
        if r.status_code == 200:
            titles = sorted(set(re.findall(r"[A-Za-z0-9_ ]*(?:Router|Switch|Firewall|Network|Cisco|Juniper)[A-Za-z0-9_ ]*STIG[A-Za-z0-9_ .\-]*", r.text)))[:100]
    except Exception as e:
        titles = [f"ERR: {e}"]
    OUT.write_text(json.dumps({"source": INDEX, "stig_titles": titles,
                               "note": "Download full XCCDF from cyber.mil and use import_xccdf()."}, indent=2), encoding="utf-8")
    return {"ok": True, "titles": len(titles), "out": str(OUT)}


def import_xccdf(xml_path: str | Path) -> dict:
    ns = {"x": "http://checklists.nist.gov/xccdf/1.2"}
    tree = ET.parse(str(xml_path))
    groups = tree.getroot().findall("x:Group", ns)
    rows = []
    for g in groups:
        rule = g.find("x:Rule", ns)
        rows.append({"group_id": g.get("id"),
                     "rule_id": rule.get("id") if rule is not None else "",
                     "severity": (rule.get("severity") if rule is not None else "").upper(),
                     "title": (g.findtext("x:title", default="", namespaces=ns) or "").strip(),
                     "description": (g.findtext("x:description", default="", namespaces=ns) or "").strip()[:2000]})
    return {"total": len(rows), "controls": rows}


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(json.dumps(import_xccdf(sys.argv[1]) | {"imported": sys.argv[1]}, indent=2)[:4000])
    else:
        print(json.dumps(scrape(), indent=2))
