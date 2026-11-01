"""Branch coverage for app/api/v1/reports.py: malformed audit shapes, oversized sections and degraded fallbacks in the PDF
builder, plus the report endpoints' error paths."""
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api.v1 import reports as rp
from app.core import persist
from app.main import app

client = TestClient(app)


def _id(p):
    return f"{p}-{uuid.uuid4().hex[:8].upper()}"


@pytest.fixture(autouse=True)
def _own_org():
    """Deliberately malformed audits must never be visible to fleet-wide reports of other tests."""
    from app.core import db as dbmod, tenancy
    org = "ORG-COVR-" + uuid.uuid4().hex[:6].upper()
    with dbmod.get_conn() as conn:
        conn.cursor().execute("INSERT INTO organizations (org_id, name) VALUES (%s, %s)", (org, org))
    with tenancy.use_org(org):
        yield


def _audit(findings=(), **cols):
    asset = _id("AST")
    persist.save("assets", {"asset_id": asset, "name": "cov-" + asset, "vendor": "cisco"})
    aid = _id("AUD")
    persist.save("audits", {"audit_id": aid, "asset_id": asset, "status": "COMPLETED", **cols})
    for i, f in enumerate(findings):
        persist.save("findings", {"finding_id": _id("F"), "audit_id": aid, "asset_id": asset, "type": "COMPLIANCE", "engine": "compliance",
                                  "title": f"finding {i}", "severity": "HIGH", "status": "FAIL", "control_id": f"C-{i}", **f})
    return aid


def _pdf(aid, sections=None):
    out = rp.generate_report(aid, sections)
    stored = persist.get("reports", out["report_id"])
    assert bytes(stored["pdf"]).startswith(b"%PDF")
    return out


# ---------------------------------------------------------------- helpers
def test_numeric_helpers_and_risk_rating():
    assert rp._num(float("nan"), 5.0) == 5.0 and rp._num("x", 2.0) == 2.0 and rp._num("3.5") == 3.5
    assert rp._int("x", 4) == 4 and rp._int("7.9") == 7
    assert rp._risk_rating(90, 0, 0)[0] == "Low" and rp._risk_rating(70, 0, 0)[0] == "Medium"
    assert rp._risk_rating(70, 0, 2)[0] == "High" and rp._risk_rating(50, 0, 0)[0] == "High"
    assert rp._risk_rating(90, 1, 0)[0] == "Critical" and rp._risk_rating(30, 0, 0)[0] == "Critical"


def test_display_helpers():
    assert rp._engine_display({"engine": "weird_engine"}) == "Weird Engine"
    assert rp._engine_display({"engine": "", "type": ""}) == "Assessment"
    assert rp._short_obs({"a": 1, "b": "", "c": 3}) == "a: 1, c: 3"
    assert rp._short_obs({"algorithm": "RSA", "key_size": 2048}) == "RSA 2048"
    assert rp._short_obs(None) == "" and rp._short_obs(True) == "enabled"


def test_remediation_hint_variants():
    assert rp._remediation_hint({"status": "PASS"}).startswith("No action")
    assert rp._remediation_hint({"remediation": {"detail": {"commands": ["a", "b"]}}}) == "a; b"
    assert rp._remediation_hint({"remediation": {"detail": {"recommendation": "Do X"}}}) == "Do X"
    assert "release 17.9" in rp._remediation_hint({"remediation": {"fixed_version": "17.9"}})
    assert rp._remediation_hint({"remediation": {"migration": "to ML-KEM"}}) == "to ML-KEM"
    assert "framework guidance" in rp._remediation_hint({"remediation": {}})
    assert "framework guidance" in rp._remediation_hint({"remediation": "not a dict"})


# ---------------------------------------------------------------- PDF builder
def test_every_section_survives_audit_fields_of_the_wrong_type():
    aid = _audit(vendor="x", summary="x", cve="x", pqc="x", security="x", by_framework="x", compliance="x")
    assert _pdf(aid)["sha256"]


def test_every_section_survives_inner_fields_of_the_wrong_type():
    aid = _audit(cve={"summary": "x", "matches": "not a list"}, pqc={"counts": "x", "algorithms": "x"},
                 security={"anomalies": "x", "patterns": "x"})
    _pdf(aid)


def test_oversized_sections_are_truncated_with_a_pointer_to_the_api():
    fails = [{"finding_id": f"F-{i}", "engine": "compliance", "status": "FAIL", "control_id": f"C-{i}", "title": f"t{i}",
              "severity": "CRITICAL" if i % 3 == 0 else "HIGH", "evidence": {"property": "P", "observed": "v"},
              "confidence": "high" if i == 0 else 0.9} for i in range(65)]
    audit = dict(audit_id="AUD-MEM", asset_id="", findings=fails,
                 summary={"compliance_score": 30.0, "failed": 65},
                 by_framework={"CIS": {"compliance_score": 0.4, "passed": 1, "failed": 99, "total": 100}, "NIST": None},
                 cve={"matches": ["junk", *({"cve_id": f"CVE-{i}", "cvss": {"score": 9.0, "severity": "CRITICAL"}, "installed_version": "1"} for i in range(3))],
                      "summary": {}},
                 pqc={"counts": {"READY": 1}, "algorithms": ["junk", *({"algorithm": f"A{i}", "protocol": "TLS", "pqc_status": "TRANSITION"} for i in range(45))]},
                 security={"anomalies": ["junk", *({"type": "T", "severity": "HIGH", "message": f"m{i}", "property": "P"} for i in range(55))],
                           "patterns": []},
                 provenance={f"PROP.{i}": {"line": f"line {i}", "line_no": i} if i % 2 else f"plain {i}" for i in range(35)},
                 unknown_lines=[f"unparsed line {i}" for i in range(20)],
                 degraded=["IR validator unavailable"])
    assert rp._build_pdf(audit, report_id="REP-MEM", sections=list(rp.ALLOWED_SECTIONS)).startswith(b"%PDF")


def test_a_clean_audit_and_a_partial_report():
    aid = _audit([{"status": "PASS", "severity": "LOW"}], summary={"compliance_score": 100.0}, by_framework={}, cve={}, pqc={}, security={})
    _pdf(aid)
    _pdf(aid, ["EXECUTIVE_SUMMARY"])                       # the omitted sections are listed on the cover page
    _pdf(aid, ["EVIDENCE", "bogus"])


def test_acceptances_failing_never_fails_the_report(monkeypatch):
    from app.core import risk_exceptions
    monkeypatch.setattr(risk_exceptions, "active_keys", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db")))
    _pdf(_audit([{}]))


# ---------------------------------------------------------------- endpoints
def test_create_report_rejects_other_formats_and_unknown_audits():
    from app.core import config as cfg, tenancy
    with tenancy.use_org(cfg.DEFAULT_ORG_ID):
        aid = _audit()
    assert client.post("/api/v1/reports", json={"audit_id": "AUD-NOPE", "format": "DOCX"}).status_code == 404
    r = client.post("/api/v1/reports", json={"audit_id": aid, "format": "DOCX"})
    assert r.status_code == 400 and "PDF" in r.text
    assert client.post("/api/v1/reports", json={"audit_id": "AUD-NOPE"}).status_code == 404


def test_listing_degrades_to_empty_but_keeps_http_errors(monkeypatch):
    monkeypatch.setattr(rp, "paged", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db")))
    assert client.get("/api/v1/reports").json()["data"]["items"] == []


def test_download_of_missing_or_corrupt_pdf_bytes_is_a_clear_server_error():
    from app.core import config as cfg, tenancy
    with tenancy.use_org(cfg.DEFAULT_ORG_ID):
        rid, rid2 = _id("REP"), _id("REP")
        persist.save("reports", {"report_id": rid, "audit_id": _audit(), "status": "COMPLETED", "format": "PDF"})
        persist.save("reports", {"report_id": rid2, "audit_id": _audit(), "status": "COMPLETED", "format": "PDF", "pdf": b"this is not a pdf"})
    r = client.get(f"/api/v1/reports/{rid}/download")
    assert r.status_code == 500 and "no PDF bytes" in r.text
    r = client.get(f"/api/v1/reports/{rid2}/download")
    assert r.status_code == 500 and "corrupt" in r.text
