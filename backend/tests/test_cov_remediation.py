"""Branch coverage for app/api/v1/remediation.py: per-engine fallbacks, finding matching, degraded paths."""
import types
import uuid

import pytest
from fastapi.testclient import TestClient

from app.api.v1 import remediation as rem
from app.core import persist
from app.main import app

client = TestClient(app)


def _id(p):
    return f"{p}-{uuid.uuid4().hex[:8].upper()}"


def _asset():
    aid = _id("AST")
    persist.save("assets", {"asset_id": aid, "name": "cov-" + aid})
    return aid


# ---------------------------------------------------------------- _audit_vendor
def test_audit_vendor_handles_missing_id_and_db_errors(monkeypatch):
    assert rem._audit_vendor("") == {}
    monkeypatch.setattr(rem.db, "select", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db down")))
    assert rem._audit_vendor("AUD-x") == {}


# ---------------------------------------------------------------- _fallback_steps
def test_fallback_steps_for_pqc_with_and_without_algorithm():
    cmds, src, _ = rem._fallback_steps({"engine": "pqc", "remediation": {"migration": "use ML-KEM"},
                                        "evidence": {"observed": {"algorithm": "RSA-2048"}}})
    assert src == "pqc-migration" and cmds[0] == "Migrate RSA-2048 per migration guidance" and "Guidance: use ML-KEM" in cmds[1]
    cmds, src, _ = rem._fallback_steps({"engine": "pqc", "title": "", "evidence": {"observed": "x"}})
    assert cmds[0] == "Migrate weak crypto to PQC-safe algorithms" and src == "pqc-migration"
    cmds, _, _ = rem._fallback_steps({"engine": "pqc", "title": "TLS 1.0", "remediation": {"detail": {"migration": "m"}}})
    assert cmds[0] == "Migrate TLS 1.0 per migration guidance" and "Guidance: m" in cmds[1]


def test_fallback_steps_generic_uses_stored_commands_recommendation_or_evidence():
    cmds, src, val = rem._fallback_steps({"engine": "compliance", "remediation": {"detail": {"commands": ["a", "b"]}}})
    assert cmds == ["a", "b"] and src == "generic" and val[0] == "show running-config"
    cmds, _, _ = rem._fallback_steps({"engine": "compliance", "remediation": {"detail": {"steps": []}}})
    assert "Remediate" in cmds[0]
    cmds, _, _ = rem._fallback_steps({"engine": "compliance", "remediation": {"detail": {"fix_commands": ["x"]}}})
    assert cmds == ["x"]
    cmds, _, _ = rem._fallback_steps({"engine": "compliance", "remediation": {"detail": {"recommendation": "Do it"}}})
    assert cmds == ["Do it"]
    cmds, _, _ = rem._fallback_steps({"engine": "compliance", "control_id": "C-1",
                                      "evidence": {"property": "SSH.ENABLED", "observed_value": False, "expected_value": True}})
    assert cmds[0].startswith("Set SSH.ENABLED to True (currently False)") and "Re-run" in cmds[1]
    cmds, _, _ = rem._fallback_steps({"engine": "compliance", "control_id": "C-2", "title": "T", "evidence": {}})
    assert cmds[0].startswith("Remediate 'T' (C-2)")
    cmds, _, _ = rem._fallback_steps({"engine": "compliance"})
    assert "this control" in cmds[0]


# ---------------------------------------------------------------- _generated_plan
def test_generated_plan_is_none_without_control_or_audit_and_degrades_on_error(monkeypatch):
    okf = {"ckb": types.SimpleNamespace(controls={"C": object()}),
           "fixlib": types.SimpleNamespace(plan=lambda *a: (_ for _ in ()).throw(ValueError("template bug")))}
    base = {"finding_id": "F", "engine": "compliance", "status": "FAIL"}
    assert rem._generated_plan({**base, "engine": "cve"}, "cisco", "ios", okf) is None
    assert rem._generated_plan({**base, "control_id": "UNKNOWN-CTRL", "audit_id": "AUD-NOPE"}, "cisco", "ios", okf) is None
    assert rem._generated_plan({**base, "control_id": "C"}, "cisco", "ios", okf) is None            # no audit id
    assert rem._generated_plan({**base, "control_id": "C", "audit_id": "AUD-NOPE"}, "cisco", "ios", okf) is None
    aid = _id("AUD")
    persist.save("audits", {"audit_id": aid, "asset_id": _asset(), "status": "COMPLETED", "canonical_ir": {}, "provenance": {}})
    assert rem._generated_plan({**base, "control_id": "C", "audit_id": aid}, "cisco", "ios", okf) is None   # template bug degrades


# ---------------------------------------------------------------- get_plan branches
def _finding(**kw):
    fid, aid, asset, cid = _id("F"), _id("AUD"), _asset(), _id("CFG")
    persist.save("configurations", {"configuration_id": cid, "asset_id": asset, "config_text": "hostname R1\n",
                                    "filename": "r.cfg", "status": "UPLOADED"})
    persist.save("audits", {"audit_id": aid, "asset_id": asset, "configuration_id": cid, "status": "COMPLETED",
                            "vendor": kw.pop("vendor", {"vendor_id": "cisco", "platform": "ios-xe"}), "canonical_ir": {}})
    rec = {"finding_id": fid, "audit_id": aid, "asset_id": asset, "engine": "compliance", "type": "COMPLIANCE",
           "title": "", "severity": "HIGH", "status": "FAIL", "control_id": "NO-SUCH-CTRL", **kw}
    persist.save("findings", rec)
    return fid


def _fake_okf(vendors):
    return {"rem": types.SimpleNamespace(index={"NO-SUCH-CTRL": {"vendors": vendors, "title": "Entry title"}}),
            "ckb": types.SimpleNamespace(controls={}), "fixlib": types.SimpleNamespace(plan=lambda *a: None)}


def test_get_plan_nxos_ignores_legacy_ios_pack_and_non_dict_vendor_entries(monkeypatch):
    fid = _finding(vendor={"vendor_id": "cisco", "platform": "NX-OS"})
    monkeypatch.setattr(rem, "okf_layer", lambda: _fake_okf({"cisco": {"commands": ["ios only"]}}))
    d = client.get(f"/api/v1/remediation/{fid}").json()["data"]
    assert "ios only" not in [s["command"] for s in d["steps"]] and d["source"] == "generic"
    fid = _finding()
    monkeypatch.setattr(rem, "okf_layer", lambda: _fake_okf({"cisco": "not-a-dict"}))
    assert client.get(f"/api/v1/remediation/{fid}").json()["data"]["source"] == "generic"


def test_get_plan_uses_vendor_pack_and_falls_back_to_the_finding_title(monkeypatch):
    fid = _finding(title="Telnet enabled")
    monkeypatch.setattr(rem, "okf_layer", lambda: _fake_okf({"cisco": {"commands": ["no ip http server"], "validation": ["v"]}}))
    d = client.get(f"/api/v1/remediation/{fid}").json()["data"]
    assert d["source"] == "okf-vendor" and d["steps"][0]["command"] == "no ip http server" and d["validation"] == ["v"]
    fid = _finding(title="Telnet enabled")
    monkeypatch.setattr(rem, "okf_layer", lambda: {"rem": types.SimpleNamespace(index={}), "ckb": types.SimpleNamespace(controls={}), "fixlib": types.SimpleNamespace(plan=lambda *a: None)})
    d = client.get(f"/api/v1/remediation/{fid}").json()["data"]
    assert d["fix_title"] == "Telnet enabled" and d["source"] == "generic"


def test_get_plan_collects_references_of_every_shape(monkeypatch):
    monkeypatch.setattr(rem, "okf_layer", lambda: {"rem": types.SimpleNamespace(index={}), "ckb": types.SimpleNamespace(controls={}), "fixlib": types.SimpleNamespace(plan=lambda *a: None)})
    fid = _finding(remediation={"references": ["https://a", {"url": "https://b"}, 7, "https://a", {"nourl": 1}]})
    d = client.get(f"/api/v1/remediation/{fid}").json()["data"]
    assert d["references"] == ["https://a", "https://b", "7"]


def test_history_degrades_to_empty_on_db_error_but_keeps_http_errors(monkeypatch):
    fid = _finding()
    monkeypatch.setattr(rem, "paged", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db")))
    assert client.get(f"/api/v1/remediation/{fid}/history").json()["data"]["items"] == []
    from fastapi import HTTPException
    monkeypatch.setattr(rem, "paged", lambda *a, **k: (_ for _ in ()).throw(HTTPException(418, "teapot")))
    assert client.get(f"/api/v1/remediation/{fid}/history").status_code == 418


# ---------------------------------------------------------------- _same_finding_key
@pytest.mark.parametrize("orig,cand,expected", [
    ({"engine": "compliance", "control_id": "A"}, {"engine": "other"}, False),
    ({"engine": "cve", "source": {"cve": "CVE-1"}}, {"engine": "cve", "source": {"cve": "CVE-1"}}, True),
    ({"engine": "cve", "source": {"cve": "CVE-1"}}, {"engine": "cve", "source": {"cve": "CVE-2"}}, False),
    ({"engine": "cve", "type": "V", "source": "x"}, {"engine": "cve", "type": "V", "source": None}, True),
    ({"engine": "pqc", "evidence": {"observed": {"algorithm": "RSA"}}}, {"engine": "pqc", "evidence": {"observed": {"algorithm": "RSA"}}}, True),
    ({"engine": "pqc", "evidence": {"observed": {"algorithm": "RSA"}}}, {"engine": "pqc", "evidence": {"observed": {"algorithm": "EC"}}}, False),
    ({"engine": "pqc", "type": "T", "evidence": "x"}, {"engine": "pqc", "type": "T", "evidence": "y"}, True),
    ({"engine": "security", "source": {"analytics": "r1"}}, {"engine": "security", "source": {"analytics": "r1"}}, True),
    ({"engine": "security", "evidence": {"property": "P"}}, {"engine": "security", "evidence": {"property": "Q"}}, False),
    ({"engine": "security", "evidence": {"property": "P"}}, {"engine": "security", "evidence": {"property": "P"}}, True),
    ({"engine": "security", "type": "T", "evidence": "x"}, {"engine": "security", "type": "T", "evidence": "x"}, True),
    ({"engine": "weird", "type": "T"}, {"engine": "weird", "type": "T"}, True),
])
def test_same_finding_key_matches_per_engine(orig, cand, expected):
    assert rem._same_finding_key(orig, cand) is expected


# ---------------------------------------------------------------- apply
def test_apply_without_candidate_config_records_the_approval_only():
    fid = _finding()
    ap = client.post(f"/api/v1/remediation/{fid}/approve", json={"comment": "ok"}).json()["data"]["id"]
    d = client.post(f"/api/v1/remediation/{fid}/apply", json={"id": ap}).json()["data"]
    assert d["re_audit_status"] == "NOT_RUN" and d["verified_fixed"] is False and d["device_touched"] is False


def test_apply_with_candidate_config_survives_a_failing_before_count(monkeypatch):
    fid = _finding()
    ap = client.post(f"/api/v1/remediation/{fid}/approve", json={}).json()["data"]["id"]
    real, calls = rem.db.find, []

    def flaky(*a, **k):
        calls.append(1)
        if len(calls) == 2:                          # call 1 inflates the audit; call 2 is the "before" count; the re-audit must still work
            raise RuntimeError("db")
        return real(*a, **k)
    monkeypatch.setattr(rem.db, "find", flaky)
    r = client.post(f"/api/v1/remediation/{fid}/apply", json={"id": ap, "updated_config_text": "hostname R1\nip ssh version 2\n"})
    assert r.status_code == 200 and r.json()["data"]["fail_before"] == 0
