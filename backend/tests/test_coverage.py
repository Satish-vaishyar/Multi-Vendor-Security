"""Coverage suite: every router branch, engine row, parser edge and model fallback.

Complements test_audit_flow.py (happy paths) to reach 100% statement coverage.
"""
import copy
import io
import jwt
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core import config as cfgmod
from app.core import persist
from app.core import security as secmod
from app.services import integration as integ

client = TestClient(app)
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
BAD = ("hostname Core-Router-01\nip ssh version 1\nip http server\nline vty 0 4\n"
       " transport input telnet\nsnmp-server community public RO\nno logging\nCisco IOS-XE version 17.9.2\n")


def _login():
    r = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200
    return r.json()["data"]["access_token"]


def _asset():
    r = client.post("/api/v1/assets", json={"name": "Cov-Router", "vendor": "Cisco",
                                            "product": "IOS-XE", "version": "17.9.2"})
    assert r.status_code == 200
    return r.json()["data"]["asset_id"]


def _upload(text, asset):
    r = client.post("/api/v1/configurations/upload",
                    files={"file": ("r.txt", text.encode(), "text/plain")}, data={"asset_id": asset})
    assert r.status_code == 200
    return r.json()["data"]["configuration_id"]


def _audit(asset, cfg_id):
    r = client.post("/api/v1/audits", json={"asset_id": asset, "configuration_id": cfg_id,
                                            "frameworks": ["CIS"]})
    assert r.status_code == 200
    return r.json()["data"]["audit_id"]


# ---------- meta / auth / core ----------

def test_meta_routes():
    assert client.get("/").status_code == 200
    assert client.get("/health").json()["status"] == "healthy"
    ui = client.get("/ui")
    assert ui.status_code == 200 and "Sentinel" in ui.text


def test_auth_failures():
    assert client.post("/api/v1/auth/login",
                       json={"email": ADMIN_EMAIL, "password": "wrong!"}).status_code == 401
    assert client.get("/api/v1/auth/me").status_code == 401
    past = {"sub": "USR-001", "exp": int(time.time()) - 10}
    tok = jwt.encode(past, cfgmod.JWT_SECRET, algorithm=cfgmod.JWT_ALGORITHM)
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
    assert client.get("/api/v1/auth/me", headers={"Authorization": "Bearer garbage"}).status_code == 401
    nope = jwt.encode({"sub": "USR-NOPE", "exp": int(time.time()) + 600},
                      cfgmod.JWT_SECRET, algorithm=cfgmod.JWT_ALGORITHM)
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {nope}"}).status_code == 401


def test_core_utils():
    assert cfgmod.ok({"a": 1}, request_id="r")["request_id"] == "r"
    e = cfgmod.err("X", "y")
    assert e["success"] is False and e["error"]["code"] == "X"
    assert secmod._verify("pw", "malformed-hash") is False
    assert secmod.authenticate("nobody@example.com", "x") is None

    def boom(*a, **k):
        raise RuntimeError("no dotenv")

    import app.core.config as cmod
    real = cmod.load_dotenv
    cmod.load_dotenv = boom
    try:
        cmod._load_env()
    finally:
        cmod.load_dotenv = real


# ---------- assets / audits / configurations ----------

def test_assets_crud_edges():
    aid = _asset()
    assert client.get(f"/api/v1/assets/{aid}").status_code == 200
    assert client.get("/api/v1/assets/AST-NOPE").status_code == 404
    assert client.patch(f"/api/v1/assets/{aid}", json={"model": "Catalyst"}).status_code == 200
    assert client.patch("/api/v1/assets/AST-NOPE", json={"model": "x"}).status_code == 404
    assert client.get("/api/v1/assets", params={"vendor": "Cisco", "status": "ACTIVE"}).status_code == 200
    assert client.delete(f"/api/v1/assets/{aid}").json()["data"]["status"] == "DELETED"
    assert client.delete("/api/v1/assets/AST-NOPE").status_code == 404


def test_audit_404s():
    assert client.post("/api/v1/audits", json={"asset_id": "AST-001",
                                               "configuration_id": "CFG-NOPE"}).status_code == 404
    assert client.get("/api/v1/audits/AUD-NOPE").status_code == 404
    assert client.get("/api/v1/audits/AUD-NOPE/results").status_code == 404
    assert client.get("/api/v1/audits/AUD-NOPE/evidence").status_code == 404


def test_configuration_edges():
    asset = _asset()
    r = client.post("/api/v1/configurations/upload", files={"file": ("e.txt", b"   \n", "text/plain")},
                    data={"asset_id": asset})
    assert r.status_code == 400
    r = client.post("/api/v1/configurations/bulk-upload",
                    files=[("files", ("a.txt", BAD.encode(), "text/plain")),
                           ("files", ("b.txt", b"  ", "text/plain"))], data={"asset_id": asset})
    d = r.json()["data"]
    assert (d["accepted"], d["rejected"]) == (1, 1)
    assert client.post("/api/v1/configurations/CFG-NOPE/parse").status_code == 404
    assert client.get("/api/v1/configurations/CFG-NOPE").status_code == 404
    assert client.get("/api/v1/configurations/CFG-NOPE/canonical-ir").status_code == 404
    assert client.get("/api/v1/configurations/CFG-NOPE/unknowns").status_code == 404
    cid = _upload("blorp xyzzy nothing-here\n", asset)
    persist.update("configurations", cid, {"detected_vendor": "UNKNOWN"})
    assert client.get(f"/api/v1/configurations/{cid}").json()["data"]["parser"]["type"] == "AI_PIPELINE"


# ---------- engines api edges ----------

def test_compliance_404s():
    assert client.get("/api/v1/compliance/AUD-NOPE").status_code == 404
    asset = _asset()
    aud = _audit(asset, _upload(BAD, asset))
    assert client.get(f"/api/v1/compliance/{aud}/framework/NOPE").status_code == 404


def test_cve_db_filters():
    base = "/api/v1/vulnerabilities/cves"
    assert client.get(base).status_code == 200
    first = client.get(base).json()["data"]["items"][0]["cve_id"]
    assert client.get(base, params={"cve_id": first}).json()["data"]["total"] >= 1
    assert client.get(base, params={"vendor": "cisco"}).status_code == 200
    assert client.get(base, params={"product": "ios"}).status_code == 200
    assert client.get(base, params={"severity": "CRITICAL"}).status_code == 200


def test_cve_sync_paths(monkeypatch):
    import httpx

    corp = Path(cfgmod.OKF_DIR) / "knowledge" / "vulnerability"
    bak_cve, bak_meta = corp / "cves.json", corp / "meta.json"
    saved = (bak_cve.read_bytes() if bak_cve.exists() else None,
             bak_meta.read_bytes() if bak_meta.exists() else None)
    payload = {"vulnerabilities": [{"cve": {
        "id": "CVE-TEST-0001", "published": "2026-01-01T00:00:00", "lastModified": "2026-01-02T00:00:00",
        "descriptions": [{"lang": "en", "value": "coverage test"}], "metrics": {},
        "weaknesses": [], "references": [], "configurations": []}}]}

    class FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return copy.deepcopy(payload)

    try:
        monkeypatch.setattr(httpx, "get", lambda *a, **k: FakeResp())
        r = client.post("/api/v1/vulnerabilities/sync", json={"pages": 1, "results_per_page": 5})
        assert r.json()["data"]["status"] == "COMPLETED"
        job = r.json()["data"]["job_id"]
        assert client.get(f"/api/v1/vulnerabilities/sync/{job}").status_code == 200

        def fail(*a, **k):
            raise RuntimeError("net down")

        monkeypatch.setattr(httpx, "get", fail)
        r2 = client.post("/api/v1/vulnerabilities/sync", json={"pages": 1})
        assert r2.json()["data"]["status"] == "COMPLETED"
        assert r2.json()["data"]["job_id"]
        # malformed pages value raises inside the endpoint -> FAILED branch
        r3 = client.post("/api/v1/vulnerabilities/sync", json={"pages": "notanint"})
        assert r3.json()["data"]["status"] == "FAILED"
    finally:
        if saved[0] is not None:
            bak_cve.write_bytes(saved[0])
        if saved[1] is not None:
            bak_meta.write_bytes(saved[1])
    assert client.get("/api/v1/vulnerabilities/sync/JOB-NOPE").status_code == 404


def test_vuln_detail_edges():
    asset = _asset()
    aud = _audit(asset, _upload(BAD, asset))
    persist.save("findings", {"finding_id": "F-VDTEST", "engine": "cve", "type": "VULNERABILITY",
                                  "severity": "HIGH", "status": "FAIL", "asset_id": asset,
                                  "audit_id": aud, "title": "t"})
    assert client.get(f"/api/v1/vulnerabilities/{aud}/F-VDTEST").status_code == 200
    assert client.get(f"/api/v1/vulnerabilities/{aud}/F-NOPE").status_code == 404
    assert client.get("/api/v1/vulnerabilities/AUD-NOPE/F-VDTEST").status_code == 404


def test_pqc_analytics_404():
    assert client.get("/api/v1/pqc/AUD-NOPE").status_code == 404
    assert client.get("/api/v1/analytics/AUD-NOPE").status_code == 404
    assert client.get("/api/v1/analytics/fleet/JOB-NOPE").status_code == 404


def test_fleet_single_and_empty():
    asset = _asset()
    _audit(asset, _upload(BAD, asset))
    r = client.post("/api/v1/analytics/fleet", json={"asset_ids": [asset]}).json()["data"]
    one = client.get(f"/api/v1/analytics/fleet/{r['job_id']}").json()["data"]
    assert len(one["devices"]) == 1
    r2 = client.post("/api/v1/analytics/fleet", json={"asset_ids": ["AST-NOPE"]}).json()["data"]
    empty = client.get(f"/api/v1/analytics/fleet/{r2['job_id']}").json()["data"]
    assert empty["devices"] == []


def test_blast_404():
    r = client.post("/api/v1/vulnerabilities/blast-radius",
                    json={"cve_id": "CVE-NOPE-0000", "assets": []})
    assert r.status_code == 404


# ---------- findings / okf / remediation / reports / training ----------

def test_findings_filters_and_404():
    asset = _asset()
    aud = _audit(asset, _upload(BAD, asset))
    q = {"audit_id": aud, "severity": "HIGH", "type": "COMPLIANCE",
         "asset_id": asset, "status": "FAIL", "engine": "compliance"}
    assert client.get("/api/v1/findings", params=q).status_code == 200
    assert client.get("/api/v1/findings/F-NOPE").status_code == 404


def test_okf_browser_edges():
    assert client.get("/api/v1/okf/properties", params={"category": "remote_access"}).status_code == 200
    assert client.get("/api/v1/okf/controls",
                      params={"framework": "NIST", "category": "remote_access",
                              "severity": "HIGH"}).status_code == 200
    assert client.get("/api/v1/okf/controls/OKF-NOPE").status_code == 404
    asset = _asset()
    cid = _upload(BAD, asset)
    r = client.post("/api/v1/detection/vendor", json={"configuration_id": cid})
    assert r.json()["data"]["vendor_id"] == "cisco"
    assert client.post("/api/v1/detection/vendor", json={}).status_code == 400


def test_asset_validation_and_pagination():
    assert client.post("/api/v1/assets", json={"name": ""}).status_code == 422
    assert client.post("/api/v1/assets", json={"name": "x" * 201}).status_code == 422
    assert client.post("/api/v1/assets", json={"name": "<script>alert(1)</script>"}).status_code == 200
    assert client.get("/api/v1/assets", params={"page": 0}).status_code == 422
    assert client.get("/api/v1/assets", params={"page_size": 101}).status_code == 422


def test_remediation_edges():
    persist.save("findings", {"finding_id": "F-TESTCVE", "engine": "cve", "type": "VULNERABILITY",
                              "control_id": "NOPE", "severity": "HIGH", "status": "FAIL",
                              "asset_id": "AST-001", "audit_id": "AUD-NOPE",
                              "title": "t", "remediation": {"fixed_version": "9.9"}})
    steps = client.get("/api/v1/remediation/F-TESTCVE").json()["data"]["steps"]
    assert steps and "9.9" in steps[0]["command"]
    base = persist.get("findings", "F-TESTCVE")
    assert base is not None
    persist.save("findings", dict(base, finding_id="F-TESTCVE2", remediation={}))
    assert client.get("/api/v1/remediation/F-TESTCVE2").status_code == 200
    assert client.get("/api/v1/remediation/F-NOPE").status_code == 404
    assert client.post("/api/v1/remediation/F-NOPE/approve", json={}).status_code == 404
    assert client.post("/api/v1/remediation/F-TESTCVE/apply", json={"id": "REM-NOPE"}).status_code == 400


def test_reports_404():
    assert client.post("/api/v1/reports", json={"audit_id": "AUD-NOPE"}).status_code == 404
    assert client.get("/api/v1/reports/REP-NOPE").status_code == 404
    assert client.get("/api/v1/reports/REP-NOPE/download").status_code == 404


def test_training_edges(monkeypatch):
    asset = _asset()
    cid = _upload("blorp alpha one\nblorp beta two\n", asset)
    client.get(f"/api/v1/configurations/{cid}/unknowns")
    pend = persist.find("training", status="PENDING")
    assert len(pend) >= 2
    assert client.post("/api/v1/training/TR-NOPE/suggest").status_code == 404
    assert client.post("/api/v1/training/TR-NOPE/approve",
                       json={"canonical_property": "X"}).status_code == 404
    maps = integ.okf_layer()["maps"]
    monkeypatch.setattr(maps, "approve",
                        lambda *a, **k: SimpleNamespace(model_dump=lambda: {
                            "vendor": "t", "platform": "any", "source_token": "blorp",
                            "canonical_property": "SSH.VERSION", "canonical_value": 2,
                            "confidence": 0.9, "status": "approved"}))
    r = client.post(f"/api/v1/training/{pend[0]['training_id']}/approve",
                    json={"canonical_property": "SSH.VERSION", "canonical_value": 2})
    assert r.json()["data"]["status"] == "APPROVED"
    r = client.post(f"/api/v1/training/{pend[1]['training_id']}/reject", json={"reason": "bad"})
    assert r.json()["data"]["status"] == "REJECTED"
    assert client.post("/api/v1/training/TR-NOPE/reject", json={}).status_code == 404
    fl = client.post("/api/v1/analytics/fleet", json={"asset_ids": []}).json()["data"]
    assert client.get(f"/api/v1/training/jobs/{fl['job_id']}").status_code == 200
    assert client.get("/api/v1/training/jobs/JOB-NOPE").status_code == 404


# ---------- parser / engine units ----------

def test_ingestion_units():
    from app.parsers import ingestion
    assert ingestion.validate_upload("r.xyz", b"hostname R1\n")["warnings"]
    with pytest.raises(ValueError):
        ingestion.validate_upload("big.txt", b"x" * (ingestion.MAX_BYTES + 1))
    assert ingestion.validate_upload("r.txt", b"\xff\xfe bad \x80\nok\n")["text"]
    with pytest.raises(ValueError):
        ingestion.validate_upload("r.txt", b"  \n ")


def test_detector_units(monkeypatch):
    from app.parsers import vendor_detector
    monkeypatch.setattr(vendor_detector, "m1_predict",
                        lambda t: {"vendor": "unknown", "confidence": 0.3, "method": "t"})
    assert vendor_detector.detect_vendor("zzz qqq", "cisco")["vendor_id"] == "cisco"
    assert vendor_detector.detect_vendor("zzz qqq")["vendor"] == "UNKNOWN"


def test_pqc_units():
    from app.engines import pqc as p
    flat = {"CRYPTO.WEAK_ALGO": True, "CRYPTO.RSA_KEY_SIZE": 1024, "CRYPTO.TLS_MIN": "1.0",
            "CRYPTO.IKE_VERSION": 1, "SSH.VERSION": 1}
    cbom = p.build_cbom("A", flat, [{"vendor": "openssl", "product": "openssl",
                                     "version": "3.0", "component_type": "library"}])
    assert any(r["pqc_status"] == "MIGRATION_REQUIRED" for r in cbom)
    assert p.build_cbom("A", {"CRYPTO.RSA_KEY_SIZE": 2048, "CRYPTO.TLS_MIN": "1.2",
                              "CRYPTO.IKE_VERSION": 2}, [])
    assert p.build_cbom("A", {}, [])[0]["pqc_status"] == "UNKNOWN"
    assert p.readiness(cbom)["migration_recommendations"]


def test_security_units():
    from app.engines import security as s
    flat = {"TELNET.ENABLED": True, "HTTP.ENABLED": True, "SSH.VERSION": 1,
            "CRYPTO.WEAK_ALGO": True, "SNMP.COMMUNITY_PUBLIC": True,
            "PASSWORD.ENCRYPTED": False, "LOGGING.ENABLED": False,
            "LOGGING.REMOTE_SERVER": False, "AAA.AUTHENTICATION": False,
            "ACL.MGMT_RESTRICTED": False, "ACL.PERMIT_ANY": True,
            "MGMT.INTERNET_EXPOSED": True, "SSH.ENABLED": True, "AAA.MFA": False}
    out = s.analyze(flat, "A")
    assert out["patterns"] and out["count"] > 5
    clean = s.analyze({}, "A")
    assert clean["patterns"] == [] and clean["risk_score"] == 100


def test_pqc_finding_e2e():
    asset = _asset()
    cfg_txt = ("hostname R1\ncrypto key generate rsa modulus 1024\n"
               "ip ssh version 2\nCisco IOS-XE version 17.9.2\n")
    aud = _audit(asset, _upload(cfg_txt, asset))
    res = client.get(f"/api/v1/audits/{aud}/results").json()["data"]
    assert any(f["engine"] == "pqc" for f in res["findings"])


# ---------- integration fallbacks ----------

def test_integration_fallbacks(monkeypatch, tmp_path):
    import sys
    monkeypatch.setattr(cfgmod, "MODELS_DIR", str(tmp_path))
    # modules persist across calls now: evict the cached ones so the import
    # inside each wrapper really fails and the fallback branch runs
    monkeypatch.delitem(sys.modules, "src.m1_vendor", raising=False)
    assert integ.m1_predict("x")["method"].startswith("fallback")
    monkeypatch.delitem(sys.modules, "src.m6_risk", raising=False)
    assert integ.m6_rule_score("high", "internet", "critical") > 0
    monkeypatch.delitem(sys.modules, "src.common", raising=False)
    assert integ.m2_score_batch(["cmd one"])[0]["label"] == "unknown"
    monkeypatch.delitem(sys.modules, "src.m3_mapping", raising=False)
    assert integ.m3_suggest("x")[0].get("error")
    monkeypatch.delitem(sys.modules, "src.m5_validator", raising=False)
    assert integ.m5_validate({})["valid"] is True
    monkeypatch.delitem(sys.modules, "src.m7_fleet", raising=False)
    out = integ.m7_fit_fleet([{}])
    assert out["method"].startswith("fallback")
    monkeypatch.delitem(sys.modules, "src.embed", raising=False)
    assert integ.m8_dedup(["a", "a"]) == [0, 1]


def test_integration_m2_m7_branches(monkeypatch):
    import sys
    assert integ.m2_score_batch([]) == []
    one = integ.m7_fit_fleet([integ.okf_flat_to_m7({})])
    assert one["method"] == "none" and one["outliers"] == [False]
    good = {"services.ssh.version": 2, "services.telnet": False, "services.http": False,
            "logging.enabled": True, "aaa.authentication": True, "crypto.key_size": 2048}
    bad = {"services.ssh.version": 1, "services.telnet": True, "services.http": True,
           "logging.enabled": False, "aaa.authentication": False, "crypto.key_size": 1024}
    native = integ.m7_fit_fleet([good, good, good, dict(bad)])
    assert native["method"] == "hdbscan" and len(native["outliers"]) == 4
    monkeypatch.setitem(sys.modules, "hdbscan", None)
    km = integ.m7_fit_fleet([good, good, good, dict(bad)])
    assert km["method"] == "kmeans" and sum(km["outliers"]) >= 1


def test_bridge_coexistence():
    """Both `src` trees stay importable in one process (no per-call eviction)."""
    integ._ensure_bridge()
    import src.property_registry  # noqa: F401 (okf side)
    import src.m1_vendor  # noqa: F401 (models side)
    import src.m7_fleet  # noqa: F401
    assert integ.m1_predict("line vty 0 4")["vendor"] == "cisco"


def test_bridge_wrong_src_guard(monkeypatch, tmp_path):
    import sys
    import types
    fake = types.ModuleType("src")
    fake.__file__ = str(tmp_path / "src" / "__init__.py")
    monkeypatch.setitem(sys.modules, "src", fake)
    with pytest.raises(RuntimeError):
        integ._ensure_bridge()


def test_cve_sync_job_failed_marks():
    r = client.post("/api/v1/vulnerabilities/sync", json={"pages": "notanint"})
    assert r.json()["data"]["status"] == "FAILED"


def test_canonical_without_parse_first():
    asset = _asset()
    cid = _upload(BAD, asset)
    r = client.get(f"/api/v1/configurations/{cid}/canonical-ir")
    assert r.status_code == 200 and r.json()["success"]


def test_compliance_frameworks_and_one():
    assert client.get("/api/v1/compliance/frameworks").json()["data"]
    asset = _asset()
    aud = _audit(asset, _upload(BAD, asset))
    r = client.get(f"/api/v1/compliance/{aud}/framework/CIS")
    assert r.json()["data"]["framework"] == "CIS"


def test_report_get():
    asset = _asset()
    aud = _audit(asset, _upload(BAD, asset))
    rid = client.post("/api/v1/reports", json={"audit_id": aud}).json()["data"]["report_id"]
    assert client.get(f"/api/v1/reports/{rid}").json()["data"]["status"] == "COMPLETED"


def test_pqc_rsa_nonnumeric():
    from app.engines import pqc as p
    rows = p.build_cbom("A", {"CRYPTO.RSA_KEY_SIZE": "huge"}, [])
    assert rows[0]["key_size"] == 0


def test_detector_hint_word(monkeypatch):
    from app.parsers import vendor_detector
    monkeypatch.setattr(vendor_detector, "m1_predict",
                        lambda t: {"vendor": "unknown", "confidence": 0.3, "method": "t"})
    assert vendor_detector.detect_vendor("xyz junos qqq")["vendor_id"] == "juniper"


def test_audit_versions_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(cfgmod, "OKF_DIR", tmp_path)
    asset = _asset()
    aud = _audit(asset, _upload(BAD, asset))
    vers = client.get(f"/api/v1/audits/{aud}/results").json()["data"]["versions"]
    assert vers["okf"] == "1.0.0"


def test_m2_direct_and_kmeans_k1(monkeypatch):
    import sys
    out = integ.m2_score_batch(["hyperflux enable neuro-route"])
    assert "oov_score" in out[0]
    good = {"services.ssh.version": 2, "services.telnet": False, "services.http": False,
            "logging.enabled": True, "aaa.authentication": True, "crypto.key_size": 2048}
    monkeypatch.setitem(sys.modules, "hdbscan", None)
    two = integ.m7_fit_fleet([dict(good), dict(good)])
    assert two["method"] == "kmeans" and two["outliers"] == [False, False]
