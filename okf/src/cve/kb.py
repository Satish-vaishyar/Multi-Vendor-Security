"""Local Vulnerability KB (cve_okf §4, §14): JSON store + in-memory index.

Layout: knowledge/vulnerability/{cves.json, meta.json}
Record: {cve_id, description, published, last_modified, source,
          cvss:{version,base_score,severity,vector},
          cwe[], references[], affected:[{vendor,product,cpe,affected_versions:[{start,start_inclusive,end,end_inclusive,fixed}]}]}
"""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).parent.parent.parent
VULN = ROOT / "knowledge" / "vulnerability"
STORE = VULN / "cves.json"
META = VULN / "meta.json"


def _atomic_write(path: Path, text: str) -> None:
    """Write-then-rename so a crash/concurrent reader never sees a truncated KB."""
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


class VulnKB:
    def __init__(self) -> None:
        self.records: List[Dict[str, Any]] = []
        self.by_product: Dict[tuple, List[Dict]] = {}
        self._pos: Dict[str, int] | None = None     # cve_id -> index, built lazily for O(1) upsert

    # Process-wide parsed-record cache so every audit/correlate call does not
    # re-read + re-parse a multi-MB KB file. Invalidated by path/mtime/size,
    # so NVD syncs (save() rewrites the file) are picked up immediately.
    _cache: Dict[str, Any] = {"key": None, "records": []}

    @staticmethod
    def _cache_key() -> tuple | None:
        try:
            st = STORE.stat()
            return (str(STORE), st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def load(self) -> "VulnKB":
        key = self._cache_key()
        if key is not None and VulnKB._cache.get("key") == key:
            self.records = list(VulnKB._cache["records"])   # copy: callers mutate (upsert/drop)
            self._index()
            return self
        self.records = json.loads(STORE.read_text(encoding="utf-8")) if STORE.exists() else []
        self._index()
        if key is not None:
            VulnKB._cache = {"key": key, "records": self.records}
        return self

    @staticmethod
    def invalidate() -> None:
        VulnKB._cache = {"key": None, "records": []}

    def _index(self) -> None:
        self.by_product.clear()
        for r in self.records:
            for a in r.get("affected", []):
                self.by_product.setdefault(
                    ((a.get("vendor") or "").lower(), (a.get("product") or "").lower()), []).append(r)

    def save(self) -> None:
        VULN.mkdir(parents=True, exist_ok=True)
        _atomic_write(STORE, json.dumps(self.records, indent=1))
        _atomic_write(META, json.dumps({"cve_db_version": f"local-{len(self.records)}",
                                        "records": len(self.records)}, indent=1))
        self._index()

    def upsert(self, rec: Dict[str, Any]) -> None:
        # No per-record reindex here: bulk NVD syncs call this hundreds of
        # times and save() rebuilds the index once at the end (O(n) total
        # instead of O(n^2)). Call save() or _index() after a batch.
        if self._pos is None or len(self._pos) != len(self.records):
            self._pos = {r.get("cve_id"): i for i, r in enumerate(self.records)}
        i = self._pos.get(rec.get("cve_id"))
        if i is not None:
            self.records[i] = rec
        else:
            self._pos[rec.get("cve_id")] = len(self.records)
            self.records.append(rec)

    def drop_seeds(self) -> int:
        """Remove synthetic demo records so real-world results stay clean."""
        before = len(self.records)
        self._pos = None
        self.records = [r for r in self.records
                        if r.get("source") != "OKF-SEED-SYNTHETIC"]
        return before - len(self.records)

    def candidates(self, vendor: str, product: str) -> List[Dict[str, Any]]:
        return self.by_product.get(((vendor or "").lower(), (product or "").lower()), [])
