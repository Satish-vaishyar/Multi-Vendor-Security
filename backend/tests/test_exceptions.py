"""Risk acceptance workflow, findings export (CSV/JSON) and report integrity hash."""
import csv
import hashlib
import io
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from app.core import config as cfg
from app.core import db as dbmod
from app.core import rbac
from app.core import risk_exceptions as rx
from app.main import app
from tests.test_security import _auth_on, _headers, _org  # noqa: F401  (_auth_on: autouse fixture, auth enforced)

client = TestClient(app)
CORPUS = Path(cfg.OKF_DIR) / "tests" / "corpus"


def _asset(h):
    return client.post("/api/v1/assets", headers=h, json={"name": f"exc-{uuid.uuid4().hex[:6]}", "vendor": "cisco"}).json()["data"]["asset_id"]


def _audit(h, aid):
    text = (CORPUS / "cisco_iosxe_branch_insecure.cfg").read_text(encoding="utf-8")
    cid = client.post("/api/v1/configurations/upload", headers=h, data={"asset_id": aid},
                      files={"file": ("a.cfg", text.encode(), "text/plain")}).json()["data"]["configuration_id"]
    r = client.post("/api/v1/audits", headers=h, json={"asset_id": aid, "configuration_id": cid, "run_cve": False,
                                                       "frameworks": ["CIS"]})
    assert r.status_code == 200, r.text
    return r.json()["data"]["audit_id"]


def test_four_eyes_workflow_and_rbac():
    auditor, approver, approver2 = _headers(rbac.AUDITOR), _headers(rbac.APPROVER), _headers(rbac.APPROVER)
    aid = _asset(auditor)
    body = {"asset_id": aid, "finding_key": "CIS-1.1", "reason": "Legacy NMS needs it until Q4 migration", "days": 30}
    assert client.post("/api/v1/exceptions", headers=_headers(rbac.VIEWER), json=body).status_code == 403
    r = client.post("/api/v1/exceptions", headers=auditor, json=body)
    assert r.status_code == 201, r.text
    eid = r.json()["data"]["exception_id"]
    assert client.post("/api/v1/exceptions", headers=auditor, json=body).status_code == 400      # duplicate open request
    assert client.post(f"/api/v1/exceptions/{eid}/approve", headers=auditor, json={}).status_code == 403   # role
    # the requester can never approve their own request, even with approver rights
    own = client.post("/api/v1/exceptions", headers=approver, json={**body, "finding_key": "CIS-2.2"}).json()["data"]["exception_id"]
    assert client.post(f"/api/v1/exceptions/{own}/approve", headers=approver, json={}).status_code == 403
    assert client.post(f"/api/v1/exceptions/{eid}/approve", headers=approver2, json={"comment": "ok, tracked in CHG-1"}).status_code == 200
    items = client.get("/api/v1/exceptions", headers=auditor, params={"asset_id": aid}).json()["data"]["items"]
    assert {x["exception_id"]: x["active"] for x in items}[eid] is True
    assert client.post(f"/api/v1/exceptions/{eid}/approve", headers=approver2, json={}).status_code == 409   # already decided
    assert client.post(f"/api/v1/exceptions/{eid}/revoke", headers=approver2, json={}).status_code == 200
    assert not [x for x in client.get("/api/v1/exceptions", headers=auditor).json()["data"]["items"]
                if x["exception_id"] == eid and x["active"]]
    assert client.post("/api/v1/exceptions/EXC-NOPE/reject", headers=approver, json={}).status_code == 404


def test_validation_limits_and_tenant_isolation():
    h = _headers(rbac.AUDITOR)
    aid = _asset(h)
    base = {"asset_id": aid, "finding_key": "K", "reason": "a sufficiently long reason", "days": 30}
    assert client.post("/api/v1/exceptions", headers=h, json={**base, "reason": "short"}).status_code == 400
    assert client.post("/api/v1/exceptions", headers=h, json={**base, "days": cfg.EXCEPTION_MAX_DAYS + 1}).status_code == 400
    assert client.post("/api/v1/exceptions", headers=h, json={**base, "days": 0}).status_code == 400
    assert client.post("/api/v1/exceptions", headers=h, json={**base, "asset_id": "AST-NOPE"}).status_code == 400
    other = _headers(rbac.APPROVER, _org("ORG-EXC-OTHER"))
    eid = client.post("/api/v1/exceptions", headers=h, json=base).json()["data"]["exception_id"]
    assert client.post(f"/api/v1/exceptions/{eid}/approve", headers=other, json={}).status_code == 404
    assert eid not in {x["exception_id"] for x in client.get("/api/v1/exceptions", headers=other).json()["data"]["items"]}


def test_expired_acceptance_is_not_active():
    h = _headers(rbac.AUDITOR)
    aid = _asset(h)
    eid = client.post("/api/v1/exceptions", headers=h, json={"asset_id": aid, "finding_key": "K2", "days": 5,
                                                              "reason": "temporary exception for testing"}).json()["data"]["exception_id"]
    client.post(f"/api/v1/exceptions/{eid}/approve", headers=_headers(rbac.APPROVER), json={})
    with dbmod.get_conn() as conn:
        conn.cursor().execute("UPDATE finding_exceptions SET expires_at = now() - interval '1 day' WHERE exception_id=%s", (eid,))
    row = [x for x in client.get("/api/v1/exceptions", headers=h).json()["data"]["items"] if x["exception_id"] == eid][0]
    assert row["active"] is False


def test_export_shows_acceptance_csv_and_hash():
    h, appr = _headers(rbac.AUDITOR), _headers(rbac.APPROVER)
    aid = _asset(h)
    audit_id = _audit(h, aid)
    js = client.get(f"/api/v1/reports/export/{audit_id}", headers=h, params={"format": "json"})
    assert js.status_code == 200
    assert hashlib.sha256(js.content).hexdigest() == js.headers["X-Content-SHA256"]
    findings = js.json()["findings"]
    assert findings and not any(f["accepted"] for f in findings)
    target = next(f for f in findings if f["status"] == "FAIL" and f["finding_key"])
    eid = client.post("/api/v1/exceptions", headers=h, json={"asset_id": aid, "finding_key": target["finding_key"], "days": 30,
                                                              "reason": "accepted by CISO ticket SEC-42"}).json()["data"]["exception_id"]
    client.post(f"/api/v1/exceptions/{eid}/approve", headers=appr, json={})
    rows = client.get(f"/api/v1/reports/export/{audit_id}", headers=h, params={"format": "json"}).json()["findings"]
    acc = [r for r in rows if r["accepted"]]
    assert acc and all(r["finding_key"] == target["finding_key"] and r["acceptance_reason"] for r in acc)
    assert len(rows) == len(findings)                                  # accepted findings are never hidden
    c = client.get(f"/api/v1/reports/export/{audit_id}", headers=h)
    assert c.headers["content-type"].startswith("text/csv")
    parsed = list(csv.DictReader(io.StringIO(c.content.decode("utf-8-sig"))))
    assert len(parsed) == len(findings) and "accepted_until" in parsed[0]
    assert client.get(f"/api/v1/reports/export/{audit_id}", headers=h, params={"format": "xml"}).status_code == 400
    assert client.get("/api/v1/reports/export/AUD-NOPE", headers=h).status_code == 404


def test_csv_formula_injection_is_neutralised():
    from app.api.v1.reports import _csv_safe
    assert _csv_safe('=HYPERLINK("http://x")').startswith("'=") and _csv_safe("@SUM(A1)").startswith("'@")
    assert _csv_safe("+1") == "'+1" and _csv_safe("normal") == "normal" and _csv_safe(None) == ""


def test_report_carries_integrity_hash():
    h = _headers(rbac.AUDITOR)
    audit_id = _audit(h, _asset(h))
    rep = client.post("/api/v1/reports", headers=h, json={"audit_id": audit_id, "sections": ["executive"]}).json()["data"]
    d = client.get(rep["download_url"], headers=h)
    assert d.status_code == 200
    digest = hashlib.sha256(d.content).hexdigest()
    assert digest == rep["sha256"] == d.headers["X-Content-SHA256"]
    assert client.get(f"/api/v1/reports/{rep['report_id']}", headers=h).json()["data"]["sha256"] == digest


def test_finding_key_derivation():
    assert rx.finding_key({"control_id": "CIS-1"}) == "CIS-1"
    assert rx.finding_key({"source": {"cve": "CVE-1"}}) == "CVE-1"
    assert rx.finding_key({"source": {"rule": "SA-X"}}) == "SA-X"
    assert rx.finding_key({"title": "t"}) == "t"
