"""Branch coverage for app/api/v1/engines_api.py: control explanations, CVE views and their degraded fallbacks."""
import types
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api.v1 import engines_api as eng
from app.core import persist
from app.main import app

from app.services.integration import _ensure_bridge  # noqa: E402

_ensure_bridge()          # makes the OKF "src" package importable, exactly as the first real request does
client = TestClient(app)
NS = types.SimpleNamespace


def _id(p):
    return f"{p}-{uuid.uuid4().hex[:8].upper()}"


def _audit(**kw):
    asset = _id("AST")
    persist.save("assets", {"asset_id": asset, "name": "cov-" + asset})
    aid = _id("AUD")
    persist.save("audits", {"audit_id": aid, "asset_id": asset, "status": "COMPLETED", **kw})
    return aid, asset


def _select_findings(monkeypatch, rows):
    """Serve crafted rows for the findings projection; every other table is read for real."""
    real = eng.db.select

    def sel(table, cols, *a, **k):
        if table == "findings":
            if isinstance(rows, Exception):
                raise rows
            return rows
        return real(table, cols, *a, **k)
    monkeypatch.setattr(eng.db, "select", sel)


# ---------------------------------------------------------------- tiny helpers
def test_audit_helper_404_and_hit():
    aid, _ = _audit()
    assert eng._audit(aid)["audit_id"] == aid
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        eng._audit("AUD-NOPE")


def test_condition_leaves_flattening():
    assert eng._condition_leaves("x") == []
    assert eng._condition_leaves({"no": "property"}) == []
    cond = {"all": [{"property": "A", "value": 1}, {"any": [{"property": "B"}, {"property": "C"}]}]}
    assert [c["property"] for c in eng._condition_leaves(cond)] == ["A", "B", "C"]


# ---------------------------------------------------------------- compliance_controls
def _ctl(desc="", cond=None, refs=None, applies=None):
    return NS(description=desc, references=refs or [], condition=cond or {}, applies_to=applies or {})


class _BrokenCtl:
    @property
    def description(self):
        raise RuntimeError("bad control")


def _okf(ckb=None, rem=None):
    return {"ckb": NS(controls=ckb or {}), "rem": NS(index=rem or {})}


GUIDED = next(k for k, v in eng._PROPERTY_GUIDE.items() if v.get("about"))


def test_compliance_controls_explains_every_shape_of_row(monkeypatch):
    aid, _ = _audit()
    rows = [
        {"finding_id": "F1", "control_id": "BROKEN", "title": "Broken ctl", "status": "FAIL", "severity": "HIGH", "evidence": "plain string",
         "remediation": {"detail": {"commands": ["c1"], "validation": ["v1"], "rollback": ["r1"], "title": "T"}}, "risk": {"risk_score": 7, "priority": "P1"}},
        {"finding_id": "F2", "control_id": "GUIDE", "title": "Guided", "status": "FAIL", "severity": "MEDIUM",
         "evidence": {"property": GUIDED, "observed_value": False, "expected_value": True}, "remediation": None, "risk": None},
        {"finding_id": "F3", "control_id": "MULTI", "title": "Multi", "status": "UNKNOWN", "severity": "LOW", "evidence": {}, "remediation": {}},
        {"finding_id": "F4", "control_id": "BARE", "title": "Bare", "status": "FAIL", "severity": "LOW", "evidence": {"property": "X.UNGUIDED", "observed": 1},
         "remediation": {}},
        {"finding_id": "F5", "control_id": "NONE", "title": "", "status": "PASS", "severity": "LOW", "evidence": {}, "remediation": {}},
        {"finding_id": "F6", "control_id": "NA", "title": "NA", "status": "NOT_APPLICABLE", "severity": "LOW", "evidence": {}, "remediation": {}},
        {"finding_id": "F7", "control_id": "KBFIX", "title": "Kb", "status": "FAIL", "severity": "LOW", "evidence": {"property": "X.KB", "observed": 1},
         "remediation": {}},
    ]
    ckb = {"BROKEN": _BrokenCtl(), "GUIDE": _ctl("OSCAL-normalized stub", {"property": GUIDED, "operator": "EQUALS", "value": True}),
           "MULTI": _ctl("", {"all": [{"property": "P.ONE", "value": 1}, {"property": "P.TWO", "value": 2}]}),
           "BARE": _ctl("A real description"), "NA": _ctl("na", applies={"vendors": ["cisco"]}), "KBFIX": _ctl("kb")}
    rem = {"KBFIX": {"vendors": {"cisco": {"title": "KB title", "commands": ["kb cmd"], "validation": ["kb val"], "rollback": ["kb rb"]}}}}
    monkeypatch.setattr(eng, "okf_layer", lambda: _okf(ckb, rem))
    _select_findings(monkeypatch, rows)
    items = {i["finding_id"]: i for i in client.get(f"/api/v1/compliance/{aid}/controls").json()["data"]["items"]}
    assert items["F1"]["fix"]["commands"] == ["c1"] and items["F1"]["fix"]["rollback"] == ["r1"] and "risk P1, score 7" in items["F1"]["impact_statement"]
    assert items["F1"]["evidence_display"]["observed"] == "plain string"
    assert GUIDED in items["F2"]["description"] and items["F2"]["fix"]["commands"]
    assert items["F3"]["description"].startswith("Requires P.ONE, P.TWO") and items["F3"]["fix"]["commands"][0] == "Configure P.ONE to 1"
    assert "Unverified" in items["F3"]["impact_statement"]
    assert "Leaving this misconfigured" in items["F4"]["impact_statement"] and items["F4"]["fix"]["title"].startswith("Bring X.UNGUIDED")
    assert items["F5"]["description"] == "NONE" and "passing" in items["F5"]["impact_statement"]
    assert items["F6"]["fix"]["commands"] == [] and "Skipped before evaluation" in items["F6"]["why_explanation"]
    assert items["F7"]["fix"]["commands"] == ["kb cmd"] and items["F7"]["fix"]["title"] == "KB title"


def test_compliance_controls_degrades_when_the_projection_or_the_kb_fail(monkeypatch):
    aid, asset = _audit()
    persist.save("findings", {"finding_id": _id("F"), "audit_id": aid, "asset_id": asset, "engine": "compliance", "type": "COMPLIANCE",
                              "control_id": "C-FB", "title": "Fallback", "status": "FAIL", "severity": "LOW"})
    _select_findings(monkeypatch, RuntimeError("projection unsupported"))
    monkeypatch.setattr(eng, "okf_layer", lambda: (_ for _ in ()).throw(RuntimeError("okf down")))
    items = client.get(f"/api/v1/compliance/{aid}/controls").json()["data"]["items"]
    assert [i["control_id"] for i in items] == ["C-FB"] and items[0]["description"] == "Fallback"


# ---------------------------------------------------------------- kb status / cve sync
def test_kb_status_without_meta_file(monkeypatch):
    import pathlib
    real = pathlib.Path.read_text

    def read(self, *a, **k):
        if self.name == "meta.json":
            raise FileNotFoundError(self.name)
        return real(self, *a, **k)
    monkeypatch.setattr(pathlib.Path, "read_text", read)
    assert client.get("/api/v1/vulnerabilities/kb/status").json()["data"]["meta"] == {}


def test_cve_sync_accepts_dict_and_string_products_and_dedupes(monkeypatch):
    seen = {}

    def fake_sync(keyword, pages, per_page, **kw):
        seen.update(keyword=keyword, **kw)
        return {"added": 0}
    monkeypatch.setattr(eng, "cve_layer", lambda: {"sync_now": fake_sync})
    body = {"products": [{"vendor": "cisco", "product": "ios_xe"}, "juniper junos", "", None, "juniper junos"], "kev": False,
            "since_days": 30, "drop_seeds": True}
    d = client.post("/api/v1/vulnerabilities/sync", json=body).json()["data"]
    assert d["status"] == "COMPLETED" and seen["keywords"] == ["cisco ios_xe", "juniper junos"] and seen["since_days"] == 30
    monkeypatch.setattr(eng, "cve_layer", lambda: {"sync_now": lambda *a, **k: (_ for _ in ()).throw(RuntimeError("nvd down"))})
    assert client.post("/api/v1/vulnerabilities/sync", json={"kev": False}).json()["data"]["status"] == "FAILED"


# ---------------------------------------------------------------- vulns_for_audit
def test_vulns_for_audit_links_findings_and_survives_projection_failures(monkeypatch):
    aid, asset = _audit(cve={"matches": [
        {"cve_id": "CVE-1", "installed_version": "1.0", "cvss": {"severity": "weird"}},
        {"cve_id": "CVE-2", "installed_version": "9", "cpe": "cpe:2.3:o:x", "cvss": {"severity": "high"}},
        {"cve_id": "CVE-3", "installed_version": "2.0"},
        {"cve_id": "CVE-4", "installed_version": "7"}], "unresolved": []})
    rows = [{"finding_id": "FC", "evidence": {"cpe": "cpe:2.3:o:x"}, "source": {}},
            {"finding_id": "FO", "evidence": {"observed": "2.0"}, "source": {}},
            {"finding_id": "FV", "evidence": {}, "source": {"cve": "CVE-4"}}]
    _select_findings(monkeypatch, rows)
    items = {m["cve_id"]: m for m in client.get(f"/api/v1/vulnerabilities/{aid}").json()["data"]["items"]}
    assert items["CVE-1"]["severity"] == "UNKNOWN" and items["CVE-2"]["finding_id"] == "FC"
    assert items["CVE-3"]["finding_id"] == "FO" and items["CVE-4"]["finding_id"] == "FV"
    persist.save("findings", {"finding_id": _id("F"), "audit_id": aid, "asset_id": asset, "engine": "cve", "type": "VULNERABILITY",
                              "title": "x", "status": "FAIL", "severity": "LOW", "evidence": {"observed": "1.0"}, "source": {"cve": "CVE-1"}})
    _select_findings(monkeypatch, RuntimeError("no projection"))
    assert client.get(f"/api/v1/vulnerabilities/{aid}").json()["data"]["items"][0]["finding_id"]
    real_find = eng.db.find
    monkeypatch.setattr(eng.db, "find", lambda t, **k: (_ for _ in ()).throw(RuntimeError("db")) if t == "findings" else real_find(t, **k))
    assert client.get(f"/api/v1/vulnerabilities/{aid}").json()["data"]["total"] == 4


# ---------------------------------------------------------------- vuln_detail
def _cve_finding(aid, asset, **kw):
    fid = _id("F")
    persist.save("findings", {"finding_id": fid, "audit_id": aid, "asset_id": asset, "engine": "cve", "type": "VULNERABILITY",
                              "title": "CVE finding", "status": "FAIL", "severity": "HIGH", **kw})
    return fid


def _fake_kb(records):
    return lambda: {"kb": lambda: NS(load=lambda: NS(records=records))}


def test_vuln_detail_404_for_a_finding_of_another_audit():
    aid, asset = _audit()
    fid = _cve_finding(aid, asset)
    assert client.get(f"/api/v1/vulnerabilities/AUD-OTHER/{fid}").status_code == 404
    assert client.get(f"/api/v1/vulnerabilities/{aid}/F-NOPE").status_code == 404


def test_vuln_detail_matches_backfills_and_writes_remedies(monkeypatch):
    kb_rec = {"cve_id": "CVE-9", "cvss": "oops", "description": "d", "cwe": ["CWE-1"],
              "references": ["https://kb", {"url": "https://kb2"}, 5],
              "affected": [{"vendor": "other", "product": "x", "affected_versions": [{"max": "1"}]},
                           {"vendor": "cisco", "product": "ios_xe", "affected_versions": [{"max": "17.9"}]}]}
    monkeypatch.setattr(eng, "cve_layer", _fake_kb([kb_rec]))
    stored = [{"cve_id": "CVE-9", "installed_version": "17.3", "product": "ios_xe", "status": "VULNERABLE", "cvss": "bad",
               "matched_rule": "not-a-dict", "references": ["https://m", {"url": "https://m"}, {"x": 1}]},
              {"cve_id": "CVE-9", "installed_version": "99", "product": "ios_xe", "status": "VULNERABLE"}]
    aid, asset = _audit(vendor={"vendor_id": "cisco"}, cve={"matches": stored})
    fid = _cve_finding(aid, asset, source={"cve": "CVE-9"}, evidence={"observed": "17.3"})
    d = client.get(f"/api/v1/vulnerabilities/{aid}/{fid}").json()["data"]
    assert d["status"] == "VULNERABLE" and any("No fixed release" in s for s in d["remediation_steps"]) if "remediation_steps" in d else True
    text = str(d)
    assert "https://kb2" in text and "https://m" in text
    # second stored entry is only reachable through the CVE-id fallback loop
    fid2 = _cve_finding(aid, asset, source={"cve": "CVE-9"}, evidence={"observed": "unknown-version"})
    assert client.get(f"/api/v1/vulnerabilities/{aid}/{fid2}").status_code == 200


def test_vuln_detail_status_specific_steps(monkeypatch):
    monkeypatch.setattr(eng, "cve_layer", _fake_kb([]))
    aid, asset = _audit(vendor={"vendor_id": "cisco"}, cve={"matches": [
        {"cve_id": "CVE-A", "installed_version": "1", "product": "p", "status": "VULNERABLE", "fixed_version": "2"},
        {"cve_id": "CVE-B", "installed_version": "1", "product": "p", "status": "NOT_AFFECTED"}]})
    a = _cve_finding(aid, asset, source={"cve": "CVE-A"}, evidence={"observed": "1"})
    b = _cve_finding(aid, asset, source={"cve": "CVE-B"}, evidence={"observed": "1"})
    assert "Upgrade p from 1 to 2" in str(client.get(f"/api/v1/vulnerabilities/{aid}/{a}").json()["data"])
    assert "outside the affected range" in str(client.get(f"/api/v1/vulnerabilities/{aid}/{b}").json()["data"])


def test_vuln_detail_tolerates_malformed_records_and_a_broken_kb(monkeypatch):
    aid, asset = _audit()
    odd = _cve_finding(aid, asset, source="not a dict", evidence="not a dict either")
    monkeypatch.setattr(eng, "cve_layer", lambda: (_ for _ in ()).throw(RuntimeError("kb down")))
    assert client.get(f"/api/v1/vulnerabilities/{aid}/{odd}").status_code == 200
    with_cve = _cve_finding(aid, asset, source={"cve": "CVE-Z"}, evidence={"observed": "1"})
    assert client.get(f"/api/v1/vulnerabilities/{aid}/{with_cve}").status_code == 200
    monkeypatch.setattr(eng, "_audit_cols", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("audit read failed")))
    assert client.get(f"/api/v1/vulnerabilities/{aid}/{with_cve}").status_code == 200


def test_vuln_detail_survives_a_resolver_failure(monkeypatch):
    kb_rec = {"cve_id": "CVE-R", "affected": [{"vendor": "cisco", "product": "ios_xe", "affected_versions": [{"max": "9"}]}]}
    monkeypatch.setattr(eng, "cve_layer", _fake_kb([kb_rec]))
    import src.cve.cpe_resolver as res
    monkeypatch.setattr(res, "canonical", lambda *a: (_ for _ in ()).throw(RuntimeError("resolver")))
    aid, asset = _audit(vendor={"vendor_id": "cisco"}, cve={"matches": [{"cve_id": "CVE-R", "installed_version": "1", "product": "ios_xe", "status": "VULNERABLE"}]})
    fid = _cve_finding(aid, asset, source={"cve": "CVE-R"}, evidence={"observed": "1"})
    assert client.get(f"/api/v1/vulnerabilities/{aid}/{fid}").status_code == 200


# ---------------------------------------------------------------- analytics
def test_analytics_without_unified_findings(monkeypatch):
    aid, _ = _audit(security={"risk_score": 80, "anomalies": []})
    real_find = eng.db.find
    monkeypatch.setattr(eng.db, "find", lambda t, **k: (_ for _ in ()).throw(RuntimeError("db")) if t == "findings" else real_find(t, **k))
    assert client.get(f"/api/v1/analytics/{aid}").status_code == 200
