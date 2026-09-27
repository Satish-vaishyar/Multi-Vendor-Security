"""API router tests (TestClient): covers src/api_okf.py + src/cve/api.py end to end.

Hermetic: gateway.chat is forced to fail so all LLM paths use the offline
heuristic (no network, deterministic). Live LLM/NVD behavior is verified
separately via demo + manual curl.
"""
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))

import llm_gateway  # noqa: E402


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(llm_gateway.gateway, "chat", lambda *a, **k:
                        llm_gateway.GatewayResponse(ok=False, model="m", error="disabled"))
    import main
    return TestClient(main.app)


AUDIT_BODY = {
    "asset_id": "RTR-001", "vendor": "cisco", "platform": "ios-xe",
    "config_text": "hostname R1\nip ssh version 1\nip http server\n"
                   "transport input telnet\nsnmp-server community public RO",
    "frameworks": ["CIS", "NIST"], "asset_criticality": "HIGH",
}


def test_root(client):
    r = client.get("/")
    assert r.status_code == 200 and r.json()["service"] == "OKF"


def test_properties_and_filter(client):
    allp = client.get("/api/v1/okf/properties").json()["data"]
    assert len(allp) >= 100
    filtered = client.get("/api/v1/okf/properties", params={"category": "crypto"}).json()["data"]
    assert filtered and all(p["category"] == "crypto" for p in filtered)


def test_controls_filters_and_detail(client):
    cis = client.get("/api/v1/okf/controls", params={"framework": "cis"}).json()["data"]
    assert cis and all("CIS" in c["frameworks"] for c in cis)
    sev = client.get("/api/v1/okf/controls", params={"severity": "CRITICAL"}).json()["data"]
    assert sev and all(c["severity"] == "CRITICAL" for c in sev)
    cat = client.get("/api/v1/okf/controls", params={"category": "crypto"}).json()["data"]
    assert cat
    d = client.get("/api/v1/okf/controls/OKF-SSH-001").json()
    assert d["success"] and d["data"]["control_id"] == "OKF-SSH-001"
    assert client.get("/api/v1/okf/controls/NOPE").json()["success"] is False


def test_crosswalk_and_frameworks(client):
    x = client.get("/api/v1/okf/crosswalk/OKF-SSH-001").json()["data"]
    assert x["control_id"] == "OKF-SSH-001" and len(x["mapped_controls"]) >= 3
    fw = client.get("/api/v1/okf/frameworks").json()["data"]
    assert {f["framework_id"] for f in fw} >= {"CIS", "NIST", "STIG", "ISO27001"}


def test_audit_and_evidence(client):
    a = client.post("/api/v1/okf/audit", json=AUDIT_BODY).json()
    assert a["success"]
    d = a["data"]
    assert d["summary"]["failed"] >= 4 and d["audit_id"].startswith("AUD-")
    by_id = {f["control_id"]: f["status"] for f in d["findings"]}
    assert by_id["OKF-SSH-001"] == "FAIL" and by_id["OKF-TELNET-001"] == "FAIL"
    assert all("risk" in (f["remediation"] or {}) for f in d["findings"])
    ev = client.get(f"/api/v1/okf/audit/{d['audit_id']}/evidence").json()
    assert ev["success"] and len(ev["data"]["items"]) == len(d["findings"])
    assert client.get("/api/v1/okf/audit/AUD-NOPE/evidence").json()["success"] is False


def test_remediation_flow(client):
    g = client.get("/api/v1/okf/remediation/OKF-TELNET-001", params={"vendor": "cisco"}).json()
    assert g["success"] and g["data"]["commands"] == ["line vty 0 4", "transport input ssh"]
    assert client.get("/api/v1/okf/remediation/NOPE").json()["success"] is False
    # apply without approval -> refused
    refused = client.post("/api/v1/okf/remediation/OKF-TELNET-001/apply",
                          json={"approval_id": "bogus", "updated_config_text": ""}).json()
    assert refused["success"] is False
    ap = client.post("/api/v1/okf/remediation/OKF-TELNET-001/approve",
                     json={"approved_by": "tester"}).json()
    assert ap["success"] and ap["data"]["status"] == "APPROVED"
    done = client.post("/api/v1/okf/remediation/OKF-TELNET-001/apply",
                       json={"approval_id": ap["data"]["approval_id"],
                             "updated_config_text": "transport input ssh\nip ssh version 2"}).json()
    assert done["success"] and done["data"]["mode"] == "SIMULATION"
    assert done["data"]["device_touched"] is False


def test_training_flow(client, monkeypatch, tmp_path):
    s = client.post("/api/v1/okf/training/suggest",
                    json={"raw_command": "ip ssh version 2", "vendor": "cisco"}).json()
    assert s["success"] and s["data"]["training_suggestions"]
    # redirect learned-file writes away from the real knowledge tree
    import src.api_okf as api

    real_approve = api.maps.approve
    written = {}

    def _fake_approve(vendor, platform, pattern, prop, value, out=None):
        m = real_approve(vendor, platform, pattern, prop, value,
                         out=tmp_path / "learned.yaml")
        written["yes"] = True
        return m

    monkeypatch.setattr(api.maps, "approve", _fake_approve)
    r = client.post("/api/v1/okf/training/approve",
                    json={"vendor": "pytesttmp", "platform": "any",
                          "pattern": "pytest-pattern", "canonical_property": "SSH.VERSION",
                          "canonical_value": 2}).json()
    assert r["success"] and written.get("yes")
    assert (tmp_path / "learned.yaml").exists()


def test_cve_endpoints(client, monkeypatch):
    a = client.post("/api/v1/okf/cve/audit",
                    json={"asset_id": "RTR-001", "vendor": "cisco", "product": "ios_xe",
                          "version": "17.9.2",
                          "config_text": "Cisco IOS-XE version 17.9.2"}).json()
    assert a["success"] and a["data"]["summary"]["vulnerable"] >= 1
    assert a["data"]["findings"] and a["data"]["cbom"]
    # explicit-only component (no config text) — production path matches real
    # NVD records only; seeds never appear even though they are in the file.
    b = client.post("/api/v1/okf/cve/audit",
                    json={"asset_id": "X", "vendor": "cisco", "product": "ios_xe",
                          "version": "17.9.4", "config_text": ""}).json()
    assert b["success"]
    assert not [m for m in b["data"]["matches"]
                if str(m.get("cve_id", "")).startswith("CVE-2024-9990")]
    kb = client.get("/api/v1/okf/cve/kb").json()["data"]
    assert kb["records"] >= 5
    import src.cve.api as capi
    monkeypatch.setattr(capi, "sync_now", lambda *a, **k: {"ok": True, "added": 1, "total": 6})
    s = client.post("/api/v1/okf/cve/sync", json={"pages": 1}).json()
    assert s["success"] and s["data"]["added"] == 1
    bl = client.post("/api/v1/okf/cve/blast-radius",
                     json={"cve_id": "CVE-2024-99904",
                           "assets": [{"asset_id": "FW-1", "vendor": "fortinet",
                                       "product": "fortios", "version": "7.2.2"}]}).json()
    assert bl["success"] and len(bl["data"]["vulnerable"]) == 1
    assert client.post("/api/v1/okf/cve/blast-radius",
                       json={"cve_id": "CVE-NOPE", "assets": []}).json()["success"] is False
