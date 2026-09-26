"""Local Vulnerability KB (cve_okf §4, §14): JSON store + in-memory index.

Layout: knowledge/vulnerability/{cves.json, meta.json}
Record: {cve_id, description, published, last_modified, source,
          cvss:{version,base_score,severity,vector},
          cwe[], references[], affected:[{vendor,product,cpe,affected_versions:[{start,start_inclusive,end,end_inclusive,fixed}]}]}
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).parent.parent.parent
VULN = ROOT / "knowledge" / "vulnerability"
STORE = VULN / "cves.json"
META = VULN / "meta.json"


class VulnKB:
    def __init__(self) -> None:
        self.records: List[Dict[str, Any]] = []
        self.by_product: Dict[tuple, List[Dict]] = {}

    def load(self) -> "VulnKB":
        self.records = json.loads(STORE.read_text(encoding="utf-8")) if STORE.exists() else []
        self._index()
        return self

    def _index(self) -> None:
        self.by_product.clear()
        for r in self.records:
            for a in r.get("affected", []):
                self.by_product.setdefault(
                    ((a.get("vendor") or "").lower(), (a.get("product") or "").lower()), []).append(r)

    def save(self) -> None:
        VULN.mkdir(parents=True, exist_ok=True)
        STORE.write_text(json.dumps(self.records, indent=1), encoding="utf-8")
        META.write_text(json.dumps({"cve_db_version": f"local-{len(self.records)}",
                                    "records": len(self.records)}, indent=1), encoding="utf-8")
        self._index()

    def upsert(self, rec: Dict[str, Any]) -> None:
        for i, r in enumerate(self.records):
            if r.get("cve_id") == rec.get("cve_id"):
                self.records[i] = rec
                self._index()
                return
        self.records.append(rec)
        self.by_product.setdefault("all", []).append(rec)
        self._index()

    def candidates(self, vendor: str, product: str) -> List[Dict[str, Any]]:
        return self.by_product.get(((vendor or "").lower(), (product or "").lower()), [])
