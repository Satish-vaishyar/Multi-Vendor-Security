"""End-to-end API tests: upload -> audit -> results/evidence -> findings ->
compliance/cve/pqc/analytics -> training loop -> remediation dry-run -> report PDF.
Also covers auth, dashboard, OKF browser, vendor detection.
"""
import os
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

BAD = ("hostname Core-Router-01\nip ssh version 1\nip http server\n"
       "line vty 0 4\n transport input telnet\n"
       "snmp-server community public RO\nno logging\nCisco IOS-XE version 17.9.2\n")
GOOD = ("hostname Core-Router-01\nip ssh version 2\nno ip http server\n"
        "ip http secure-server\nline vty 0 4\n transport input ssh\n"
        "logging host 10.0.0.99\nservice password-encryption\n")


def _login():
    r = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['data']['access_token']}"}


def _asset():
    r = client.post("/api/v1/assets", json={"name": "Core-Router-01", "vendor": "Cisco",
                                            "product": "IOS-XE", "version": "17.9.2", "criticality": "HIGH"})
    assert r.status_code == 200, r.text
    return r.json()["data"]["asset_id"]


def _upload(text, asset):
    r = client.post("/api/v1/configurations/upload",
                    files={"file": ("router.txt", text.encode(), "text/plain")},
                    data={"asset_id": asset})
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    assert d["detected_vendor"] in ("CISCO", "Cisco", "UNKNOWN", "JUNIPER")
    return d["configuration_id"]


def _audit(asset, cfg_id):
    r = client.post("/api/v1/audits", json={"asset_id": asset, "configuration_id": cfg_id,
                                            "frameworks": ["CIS", "NIST"],
                                            "run_cve": True, "run_pqc": True,
                                            "run_security_analysis": True})
    assert r.status_code == 200, r.text
    return r.json()["data"]["audit_id"]


def test_auth_and_dashboard():
    h = _login()
    assert client.get("/api/v1/auth/me", headers=h).status_code == 200
    assert client.get("/api/v1/dashboard/summary").status_code == 200


def test_full_audit_flow():
    _login()
    asset = _asset()
    cfg_id = _upload(BAD, asset)
    assert client.post(f"/api/v1/configurations/{cfg_id}/parse").status_code == 200
    assert client.get(f"/api/v1/configurations/{cfg_id}/canonical-ir").status_code == 200
    unk = client.get(f"/api/v1/configurations/{cfg_id}/unknowns")
    assert unk.status_code == 200
    aud = _audit(asset, cfg_id)
    assert client.get(f"/api/v1/audits/{aud}").status_code == 200
    res = client.get(f"/api/v1/audits/{aud}/results")
    assert res.status_code == 200
    findings = res.json()["data"]["findings"]
    assert len(findings) > 5  # compliance + cve + security + pqc unified
    assert client.get(f"/api/v1/audits/{aud}/evidence").status_code == 200
    # engine read APIs
    assert client.get(f"/api/v1/compliance/{aud}").status_code == 200
    assert client.get(f"/api/v1/compliance/{aud}/controls").status_code == 200
    assert client.get(f"/api/v1/vulnerabilities/{aud}").status_code == 200
    assert client.get(f"/api/v1/pqc/{aud}").status_code == 200
    assert client.get(f"/api/v1/analytics/{aud}").status_code == 200
    assert client.get("/api/v1/findings", params={"audit_id": aud}).status_code == 200
    fid = findings[0]["finding_id"]
    assert client.get(f"/api/v1/findings/{fid}").status_code == 200
    # training loop (queue may hold items from /unknowns)
    q = client.get("/api/v1/training/queue")
    assert q.status_code == 200
    # remediation dry-run on a compliance finding
    comp = next(f for f in findings if f["engine"] == "compliance")
    assert client.get(f"/api/v1/remediation/{comp['finding_id']}").status_code == 200
    ap = client.post(f"/api/v1/remediation/{comp['finding_id']}/approve", json={"approved_by": "test"})
    assert ap.status_code == 200
    aid = ap.json()["data"]["id"]
    dry = client.post(f"/api/v1/remediation/{comp['finding_id']}/apply",
                      json={"id": aid, "updated_config_text": GOOD})
    assert dry.status_code == 200
    assert dry.json()["data"]["device_touched"] is False
    # report PDF
    rep = client.post("/api/v1/reports", json={"audit_id": aud, "format": "PDF"})
    assert rep.status_code == 200
    rid = rep.json()["data"]["report_id"]
    dl = client.get(f"/api/v1/reports/{rid}/download")
    assert dl.status_code == 200 and dl.headers["content-type"] == "application/pdf"


def test_secure_scores_higher_than_insecure():
    _login()
    asset = _asset()
    bad = _audit(asset, _upload(BAD, asset))
    good = _audit(asset, _upload(GOOD, asset))
    sb = client.get(f"/api/v1/audits/{bad}/results").json()["data"]["summary"]["compliance_score"]
    sg = client.get(f"/api/v1/audits/{good}/results").json()["data"]["summary"]["compliance_score"]
    assert sg >= sb


def test_okf_and_detection():
    assert client.get("/api/v1/okf/properties").status_code == 200
    assert client.get("/api/v1/okf/controls", params={"framework": "NIST"}).status_code == 200
    assert client.get("/api/v1/okf/controls/OKF-SSH-001").status_code == 200
    assert client.get("/api/v1/okf/crosswalk/OKF-SSH-001").status_code == 200
    r = client.post("/api/v1/detection/vendor", json={"config_text": BAD})
    assert r.status_code == 200 and r.json()["data"]["vendor_id"] == "cisco"


def test_models_wired_m2_m3_m5_m7_m8_blast():
    _login()
    asset = _asset()
    cfg_id = _upload(BAD, asset)
    # M2 OOV scores on unknowns
    unk = client.get(f"/api/v1/configurations/{cfg_id}/unknowns").json()["data"]
    for it in unk["items"]:
        assert "oov" in it and "oov_score" in it["oov"]
    # M5 validation stored on audit + results
    aud = _audit(asset, cfg_id)
    res = client.get(f"/api/v1/audits/{aud}/results").json()["data"]
    assert "ir_validation" in res and "valid" in res["ir_validation"]
    # M3 suggestions merged into training suggest
    q = client.get("/api/v1/training/queue").json()["data"]
    assert q["total"] >= 0
    if q["total"]:
        tid = q["items"][0]["training_id"]
        sug = client.post(f"/api/v1/training/{tid}/suggest").json()["data"]
        assert "suggestions" in sug and "model_suggestions" in sug
    # M7 fleet over two audited assets
    asset2 = _asset()
    _audit(asset2, _upload(GOOD, asset2))
    fl = client.post("/api/v1/analytics/fleet", json={"asset_ids": [asset, asset2]}).json()["data"]
    fst = client.get(f"/api/v1/analytics/fleet/{fl['job_id']}").json()["data"]
    assert fst["method"] in ("hdbscan", "kmeans") and len(fst["devices"]) == 2
    # M8 dedup flag
    all_f = client.get("/api/v1/findings").json()["data"]["total"]
    ded = client.get("/api/v1/findings", params={"dedupe": True}).json()["data"]["total"]
    assert ded <= all_f
    # CVE blast-radius
    kb = client.get("/api/v1/vulnerabilities/cves").json()["data"]
    assert kb["total"] > 0
    cve_id = kb["items"][0]["cve_id"]
    bl = client.post("/api/v1/vulnerabilities/blast-radius",
                     json={"cve_id": cve_id, "assets": [
                         {"asset_id": asset, "vendor": "cisco", "product": "ios_xe", "version": "17.9.2"}]})
    assert bl.status_code == 200 and bl.json()["data"]["cve_id"] == cve_id
