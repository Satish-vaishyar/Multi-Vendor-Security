"""P2-5: fleet summary, framework evidence pack, risk acceptances in the PDF, report sign-off, white-label branding."""
import csv
import hashlib
import io
import json
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from app.api.v1 import reports as R
from app.core import config as cfg
from app.core import db as dbmod
from app.core import rbac
from app.main import app
from tests.test_security import _auth_on, _headers, _org  # noqa: F401  (_auth_on: autouse fixture, auth enforced)

client = TestClient(app)
CORPUS = Path(cfg.OKF_DIR) / "tests" / "corpus"


def _audit(h, name="cisco_iosxe_branch_insecure.cfg"):
    aid = client.post("/api/v1/assets", headers=h, json={"name": f"rm-{uuid.uuid4().hex[:6]}", "vendor": "cisco"}).json()["data"]["asset_id"]
    text = (CORPUS / name).read_text(encoding="utf-8")
    cid = client.post("/api/v1/configurations/upload", headers=h, data={"asset_id": aid},
                      files={"file": ("a.cfg", text.encode(), "text/plain")}).json()["data"]["configuration_id"]
    r = client.post("/api/v1/audits", headers=h, json={"asset_id": aid, "configuration_id": cid, "run_cve": False, "frameworks": ["CIS"]})
    assert r.status_code == 200, r.text
    return aid, r.json()["data"]["audit_id"]


def _accept(aud, appr, appr2, asset, key):
    e = client.post("/api/v1/exceptions", headers=aud, json={"asset_id": asset, "finding_key": key,
                                                              "reason": "Accepted until the Q4 migration window", "days": 30})
    assert e.status_code == 201, e.text
    assert client.post(f"/api/v1/exceptions/{e.json()['data']['exception_id']}/approve", headers=appr2, json={}).status_code == 200


def test_fleet_report_json_csv_pdf_and_rbac():
    aud, viewer = _headers(rbac.AUDITOR), _headers(rbac.VIEWER)
    asset, audit = _audit(aud)
    j = client.get("/api/v1/reports/fleet", headers=viewer).json()
    assert j["assets_audited"] >= 1 and j["by_vendor"] and j["worst_assets"] and "trend" in j
    assert any(a["asset_id"] == asset and a["audit_id"] == audit for a in j["assets"])
    assert j["open_critical_high"] >= 1 and j["top_failing_controls"]
    c = client.get("/api/v1/reports/fleet", headers=viewer, params={"format": "csv"})
    rows = list(csv.DictReader(io.StringIO(c.content.decode("utf-8-sig"))))
    assert c.headers["content-type"].startswith("text/csv") and any(r["asset_id"] == asset for r in rows)
    p = client.get("/api/v1/reports/fleet", headers=viewer, params={"format": "pdf"})
    assert p.status_code == 200 and p.content.startswith(b"%PDF")
    assert p.headers["x-content-sha256"] == hashlib.sha256(p.content).hexdigest()
    assert client.get("/api/v1/reports/fleet", headers=viewer, params={"format": "xml"}).status_code == 400
    assert client.get("/api/v1/reports/fleet").status_code == 401


def test_evidence_pack_lists_every_control_with_acceptance_shown_beside_verdict():
    aud, appr, appr2 = _headers(rbac.AUDITOR), _headers(rbac.APPROVER), _headers(rbac.APPROVER)
    asset, audit = _audit(aud)
    pack = client.get(f"/api/v1/reports/evidence/{audit}", headers=aud, params={"framework": "cis", "format": "json"}).json()
    ctrls = pack["controls"]
    assert pack["framework"] == "CIS" and len(ctrls) >= 5
    assert {c["result"] for c in ctrls} <= {"PASS", "FAIL", "N/A", "NOT_ASSESSED"}
    assert sum(pack["counts"].values()) == len(ctrls)
    fail = next(c for c in ctrls if c["result"] == "FAIL")
    assert fail["remediation"] and not fail["risk_accepted"]
    _accept(aud, appr, appr2, asset, fail["control_id"])
    pack2 = client.get(f"/api/v1/reports/evidence/{audit}", headers=aud, params={"framework": "CIS", "format": "json"}).json()
    again = next(c for c in pack2["controls"] if c["control_id"] == fail["control_id"])
    assert again["result"] == "FAIL" and again["risk_accepted"] and again["accepted_by"] and again["accepted_until"]   # verdict unchanged
    assert pack2["counts"] == pack["counts"]
    csvr = client.get(f"/api/v1/reports/evidence/{audit}", headers=aud, params={"framework": "CIS"})
    rows = list(csv.DictReader(io.StringIO(csvr.content.decode("utf-8-sig"))))
    assert len(rows) == len(ctrls) and "auditor_signoff" in rows[0]
    assert client.get(f"/api/v1/reports/evidence/{audit}", headers=aud, params={"framework": "NOPE"}).status_code == 404
    assert client.get("/api/v1/reports/evidence/AUD-NOPE", headers=aud, params={"framework": "CIS"}).status_code == 404
    assert client.get(f"/api/v1/reports/evidence/{audit}", headers=aud, params={"framework": "CIS", "format": "xml"}).status_code == 400


def test_pdf_lists_active_risk_acceptances_and_branding(monkeypatch):
    from reportlab import rl_config
    monkeypatch.setattr(rl_config, "pageCompression", 0)               # greppable PDF text
    monkeypatch.setattr(cfg, "REPORT_BRAND_NAME", "Acme Assurance")
    monkeypatch.setattr(cfg, "REPORT_BRAND_FOOTER", "Acme confidential <draft>")
    aud, appr, appr2 = _headers(rbac.AUDITOR), _headers(rbac.APPROVER), _headers(rbac.APPROVER)
    asset, audit = _audit(aud)
    fail = next(c for c in client.get(f"/api/v1/reports/evidence/{audit}", headers=aud, params={"framework": "CIS", "format": "json"})
                .json()["controls"] if c["result"] == "FAIL")
    plain = client.post("/api/v1/reports", headers=aud, json={"audit_id": audit}).json()["data"]
    pdf0 = client.get(plain["download_url"], headers=aud).content
    assert b"Risk acceptances in force" not in pdf0 and b"Acme Assurance" in pdf0 and b"Acme confidential" in pdf0
    _accept(aud, appr, appr2, asset, fail["control_id"])
    rep = client.post("/api/v1/reports", headers=aud, json={"audit_id": audit}).json()["data"]
    pdf = client.get(rep["download_url"], headers=aud).content
    assert pdf.startswith(b"%PDF") and b"Risk acceptances in force" in pdf and b"Q4 migration window" in pdf
    assert hashlib.sha256(pdf).hexdigest() == rep["sha256"]
    monkeypatch.setattr(cfg, "REPORT_BRAND_NAME", "")
    monkeypatch.setattr(cfg, "REPORT_BRAND_FOOTER", "")
    pdf_default = client.get(client.post("/api/v1/reports", headers=aud, json={"audit_id": audit}).json()["data"]["download_url"], headers=aud).content
    assert b"Acme" not in pdf_default and b"human approval required" in pdf_default       # defaults unchanged


def test_report_signoff_roles_hash_binding_audit_log_and_download_still_works():
    aud, appr, appr2 = _headers(rbac.AUDITOR), _headers(rbac.APPROVER), _headers(rbac.APPROVER)
    _asset, audit = _audit(aud)
    rep = client.post("/api/v1/reports", headers=aud, json={"audit_id": audit}).json()["data"]
    rid, url = rep["report_id"], f"/api/v1/reports/{rep['report_id']}/signoff"
    assert client.post(url, headers=aud, json={"comment": "x"}).status_code == 403            # AUDITOR cannot sign
    assert client.post("/api/v1/reports/REP-NOPE/signoff", headers=appr, json={}).status_code == 404
    r = client.post(url, headers=appr, json={"comment": "Reviewed, residual risk accepted"})
    assert r.status_code == 201, r.text
    s = r.json()["data"]
    assert s["report_sha256"] == rep["sha256"] and s["role"] == rbac.APPROVER and s["comment"].startswith("Reviewed")
    assert client.post(url, headers=appr, json={}).status_code == 409                          # one signature per person
    assert client.post(url, headers=appr2, json={}).status_code == 201                         # four-eyes not required, others may co-sign
    items = client.get(f"/api/v1/reports/{rid}/signoffs", headers=aud).json()["data"]["items"]
    assert len(items) == 2 and all(i["report_sha256"] == rep["sha256"] for i in items)
    assert client.get("/api/v1/reports/REP-NOPE/signoffs", headers=aud).status_code == 404
    dl = client.get(rep["download_url"], headers=aud)
    assert dl.status_code == 200 and dl.content.startswith(b"%PDF") and hashlib.sha256(dl.content).hexdigest() == rep["sha256"]
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM audit_log WHERE action='report.signoff' AND detail->>'report_id'=%s", (rid,))
        assert cur.fetchone()[0] == 2


def test_signoff_is_tenant_isolated():
    aud = _headers(rbac.AUDITOR)
    _a, audit = _audit(aud)
    rid = client.post("/api/v1/reports", headers=aud, json={"audit_id": audit}).json()["data"]["report_id"]
    other = _headers(rbac.APPROVER, org=_org("ORG-OTHER-RM"))
    assert client.post(f"/api/v1/reports/{rid}/signoff", headers=other, json={}).status_code == 404
    assert client.get(f"/api/v1/reports/{rid}/signoffs", headers=other).status_code == 404
    assert client.get("/api/v1/reports/fleet", headers=other).json()["assets_audited"] == 0
