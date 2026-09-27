"""NVD client tests (mocked HTTP): covers src/cve/nvd_client.py fully."""
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.cve import nvd_client as nvd  # noqa: E402
from src.cve.nvd_client import fetch_cves, normalize_nvd_item, sync  # noqa: E402


class FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def _item(cve_id, metrics=None, weaknesses=None, refs=None, nodes=None):
    return {"cve": {"id": cve_id,
                    "descriptions": [{"lang": "en", "value": "desc " + cve_id}],
                    "published": "2024-01-02T00:00Z", "lastModified": "2024-01-03T00:00Z",
                    "metrics": metrics or {},
                    "weaknesses": weaknesses or [],
                    "references": refs or [],
                    "configurations": [{"nodes": nodes or []}]}}


def test_headers_and_fetch(monkeypatch, tmp_path):
    seen = {}
    def _fake_get(url, params=None, headers=None, timeout=None):
        seen.update({"url": url, "params": params, "headers": headers})
        return FakeResp({"vulnerabilities": []})
    monkeypatch.setattr(httpx, "get", _fake_get)
    monkeypatch.setenv("NVD_API_KEY", "K123")
    fetch_cves(5, 10, keyword="cisco")
    assert seen["headers"]["apiKey"] == "K123" and seen["params"]["keywordSearch"] == "cisco"
    monkeypatch.delenv("NVD_API_KEY")
    fetch_cves()
    assert "apiKey" not in seen["headers"]


def test_normalize_metric_variants():
    v31 = _item("A", {"cvssMetricV31": [{"cvssData": {"version": "3.1", "baseScore": 9.0,
            "vectorString": "V"}, "baseSeverity": "CRITICAL"}]})
    assert normalize_nvd_item(v31)["cvss"]["severity"] == "CRITICAL"
    v30 = _item("B", {"cvssMetricV30": [{"cvssData": {"version": "3.0", "baseScore": 5.0,
            "vectorString": "V"}}]})
    assert normalize_nvd_item(v30)["cvss"]["base_score"] == 5.0
    v2 = _item("C", {"cvssMetricV2": [{"cvssData": {"version": "2.0", "baseScore": 4.0,
            "vectorString": "V"}}]})
    assert normalize_nvd_item(v2)["cvss"]["version"] == "2.0"
    nomet = _item("D")
    r = normalize_nvd_item(nomet)
    assert r["cvss"] == {} and r["cwe"] == [] and r["affected"] == []


def test_normalize_weak_refs_configs():
    item = _item("E", weaknesses=[{"description": [{"value": "CWE-79"}]}, {}],
                 refs=[{"url": "http://x", "tags": ["t"]}],
                 nodes=[{"cpeMatch": [
                     {"vulnerable": False, "criteria": "cpe:2.3:o:v:p:1:*:*:*:*:*:*:*"},
                     {"vulnerable": True, "criteria": "short"},
                     {"vulnerable": True, "criteria": "cpe:2.3:o:acme:widget:*:*:*:*:*:*:*:*",
                      "versionStartExcluding": "1.0", "versionEndExcluding": "2.0"},
                     {"vulnerable": True, "criteria": "cpe:2.3:o:acme:widget:*:*:*:*:*:*:*:*",
                      "versionStartIncluding": "1.0", "versionEndIncluding": "2.0"}]}])
    r = normalize_nvd_item(item)
    assert r["cwe"] == ["CWE-79"] and len(r["references"]) == 1
    assert len(r["affected"]) == 3  # non-vulnerable skipped
    excl = r["affected"][1]["affected_versions"][0]
    assert excl["start_inclusive"] is False and excl["end_inclusive"] is False
    incl = r["affected"][2]["affected_versions"][0]
    assert incl["start"] == "1.0" and incl["end"] == "2.0"


def test_sync_added_and_updated(monkeypatch):
    pages = [[_item("CVE-N-1"), _item("CVE-N-2"), {"cve": {"id": ""}}], [_item("CVE-N-1")]]

    class FakeKB:
        def __init__(self):
            self.records = []
            self.saved = 0

        def load(self):
            return self

        def upsert(self, rec):
            for i, r in enumerate(self.records):
                if r["cve_id"] == rec["cve_id"]:
                    self.records[i] = rec
                    return
            self.records.append(rec)

        def save(self):
            self.saved += 1

    fake = FakeKB()
    monkeypatch.setattr("src.cve.kb.VulnKB", lambda: fake)
    monkeypatch.setattr(httpx, "get",
                        lambda *a, **k: FakeResp({"vulnerabilities": pages.pop(0)}))
    out = sync(pages=2, results_per_page=2, delay=0)
    assert out == {"added": 2, "updated": 1, "dropped_seeds": 0, "total": 2} and fake.saved == 1
