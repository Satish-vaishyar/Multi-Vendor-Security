"""Lab verification of fixes: evidence-based labels, never self-asserted."""
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core import config as cfg
from app.core import db as dbmod
from app.core import rbac
from app.core import security as sec
from app.main import app
from app.services import corpus_eval, fix_lab

client = TestClient(app)
PW = "Str0ng!Passw0rd#1"
CORPUS = cfg.OKF_DIR / "tests" / "corpus"
BAD = (CORPUS / "cisco_iosxe_branch_insecure.cfg").read_text(encoding="utf-8")
GOOD = (CORPUS / "cisco_iosxe_core_hardened.cfg").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def control():
    """A control the insecure sample FAILS and the hardened sample PASSES (found from the product's own verdicts)."""
    _, bad = corpus_eval.control_statuses(BAD)
    _, good = corpus_eval.control_statuses(GOOD)
    return next(c for c, s in bad.items() if s == "FAIL" and good.get(c) == "PASS")


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setattr(cfg, "REQUIRE_AUTH", True)

    def hdr(role):
        email = f"{role.lower()}-{uuid.uuid4().hex[:8]}@example.com"
        sec.create_user(email, role.title(), PW, role, org_id=cfg.DEFAULT_ORG_ID)
        r = client.post("/api/v1/auth/login", json={"email": email, "password": PW})
        return {"Authorization": f"Bearer {r.json()['data']['access_token']}"}
    return {r: hdr(r) for r in (rbac.AUDITOR, rbac.APPROVER)}


def _upload(h, asset, text, name="r.cfg"):
    r = client.post("/api/v1/configurations/upload", headers=h, data={"asset_id": asset},
                    files={"file": (name, text.encode(), "text/plain")})
    assert r.status_code == 200, r.text
    return r.json()["data"]["configuration_id"]


def _asset(h):
    return client.post("/api/v1/assets", json={"name": "lab-" + uuid.uuid4().hex[:6]}, headers=h).json()["data"]["asset_id"]


def _verify(h, control, b, a, r=None, **kw):
    body = {"control_id": control, "before_configuration_id": b, "after_configuration_id": a, **kw}
    if r:
        body["rollback_configuration_id"] = r
    return client.post("/api/v1/remediation-verifications", json=body, headers=h)


def test_a_proven_fix_is_recorded_with_its_evidence(api, control):
    h, aid = api[rbac.APPROVER], None
    aid = _asset(h)
    b, a, r = _upload(h, aid, BAD), _upload(h, aid, GOOD), _upload(h, aid, BAD + "\n! rolled back\n")
    res = _verify(h, control, b, a, r, os_version="17.9.4", device_model="CSR1000v")
    assert res.status_code == 200, res.text
    d = res.json()["data"]
    assert d["status"] == "VERIFIED" and (d["before_status"], d["after_status"], d["rollback_status"]) == ("FAIL", "PASS", "FAIL")
    assert d["rollback_tested"] is True and d["os_version"] == "17.9.4" and "evidence" not in d
    listed = client.get(f"/api/v1/remediation-verifications?control_id={control}", headers=api[rbac.AUDITOR]).json()["data"]["items"]
    assert any(x["verification_id"] == d["verification_id"] for x in listed)
    desc = fix_lab.describe(listed[0])
    assert "Lab-verified" in desc and "CSR1000v" in desc and "rollback tested" in desc


def test_a_fix_that_did_not_work_or_a_missing_before_is_never_verified(api, control):
    h = api[rbac.APPROVER]
    aid = _asset(h)
    bad1, bad2, good = _upload(h, aid, BAD), _upload(h, aid, BAD + "\n! cosmetic change\n"), _upload(h, aid, GOOD)
    d = _verify(h, control, bad1, bad2).json()["data"]                      # config changed, control still FAIL
    assert d["status"] == "FAILED" and "did not work" in d["reason"]
    d = _verify(h, control, good, bad1).json()["data"]                      # 'before' was already fine
    assert d["status"] == "FAILED" and "nothing to fix" in d["reason"]
    still_good = _upload(h, aid, GOOD + "\n! same state\n")
    d = _verify(h, control, bad1, good, still_good).json()["data"]            # rollback did not restore the old state
    assert d["status"] == "FAILED" and "rollback did not restore" in d["reason"]
    assert fix_lab.lookup(control, "cisco", "ios-xe") is None or fix_lab.lookup(control, "cisco")["status"] == "VERIFIED"


def test_invalid_submissions_are_rejected(api, control):
    h = api[rbac.APPROVER]
    aid = _asset(h)
    b, a = _upload(h, aid, BAD), _upload(h, aid, GOOD)
    assert _verify(h, control, b, b).status_code == 400                      # same configuration twice
    assert _verify(h, control, b, _upload(h, aid, BAD)).status_code == 400   # byte-identical content: nothing changed
    assert _verify(h, control, b, "CFG-NOPE").status_code == 400
    assert _verify(h, "NO-SUCH-CONTROL", b, a).status_code == 400
    fg = (CORPUS / "fortios_fg100f_edge.cfg").read_text(encoding="utf-8")
    assert _verify(h, control, b, _upload(h, aid, fg)).status_code == 400    # different vendor
    assert _verify(h, control, b, a, b).status_code == 400                   # rollback == before


def test_only_approvers_may_record_verifications(api, control):
    h = api[rbac.APPROVER]
    aid = _asset(h)
    b, a = _upload(h, aid, BAD), _upload(h, aid, GOOD)
    assert _verify(api[rbac.AUDITOR], control, b, a).status_code == 403
    assert client.post("/api/v1/remediation-verifications", json={}, headers=h).status_code == 422


def test_the_plan_shows_lab_verified_only_after_evidence_exists(api, control):
    org = "ORG-LAB-" + uuid.uuid4().hex[:6]               # a fresh tenant: earlier tests may have verified this control elsewhere
    with dbmod.get_conn() as conn:
        conn.cursor().execute("INSERT INTO organizations (org_id, name) VALUES (%s, %s)", (org, org))
    email = f"appr-{uuid.uuid4().hex[:8]}@example.com"
    sec.create_user(email, "Appr", PW, rbac.APPROVER, org_id=org)
    tok = client.post("/api/v1/auth/login", json={"email": email, "password": PW}).json()["data"]["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    aid = _asset(h)
    b, a = _upload(h, aid, BAD), _upload(h, aid, GOOD)
    audit = client.post("/api/v1/audits", json={"asset_id": aid, "configuration_id": b, "run_cve": False,
                                                 "frameworks": ["CIS", "NIST", "STIG", "ISO27001"]}, headers=h)
    assert audit.status_code == 200, audit.text
    audit_id = audit.json()["data"]["audit_id"]
    fid = next(f["finding_id"] for f in client.get(f"/api/v1/findings?audit_id={audit_id}&status=FAIL&page_size=100", headers=h).json()["data"]["items"]
               if f.get("control_id") == control)
    before = client.get(f"/api/v1/remediation/{fid}", headers=h).json()["data"]
    assert before["verification"] != "lab-verified" and before["lab_verification"] is None
    assert _verify(h, control, b, a).json()["data"]["status"] == "VERIFIED"
    after = client.get(f"/api/v1/remediation/{fid}", headers=h).json()["data"]
    assert after["verification"] == "lab-verified" and "Lab-verified" in after["verification_note"]
    assert after["lab_verification"]["control_id"] == control and after["lab_verification"]["status"] == "VERIFIED"
    # evidence is per organisation: another tenant's plan is unchanged
    other = client.get(f"/api/v1/remediation/{fid}", headers=api[rbac.APPROVER])
    assert other.status_code == 404
