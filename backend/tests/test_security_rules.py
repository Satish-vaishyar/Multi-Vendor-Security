"""Analytics rule DSL: signals, attack paths, basis downgrade, compliance de-duplication, rule validation."""
import pytest
from app.engines import security as sec


def types(out):
    return {a["rule_id"] for a in out["anomalies"]}


def test_signal_rules_fire_with_explanations():
    out = sec.analyze({"TELNET.ENABLED": True, "SSH.VERSION": 1, "SNMP.COMMUNITY_PUBLIC": True}, "A1")
    assert {"SA-LEGACY-TELNET", "SA-CRYPTO-SSH1", "SA-CRED-SNMP-PUBLIC"} <= types(out)
    a = next(x for x in out["anomalies"] if x["rule_id"] == "SA-LEGACY-TELNET")
    assert a["why"] and a["fix"] and a["basis"] == "observed" and a["asset_id"] == "A1"
    assert out["risk_score"] < 100


def test_clean_config_has_no_findings():
    out = sec.analyze({"SSH.VERSION": 2, "AAA.AUTHENTICATION": True, "LOGGING.ENABLED": True,
                       "LOGGING.REMOTE_SERVER": True, "ACL.MGMT_RESTRICTED": True, "AAA.MFA": True})
    assert out["anomalies"] == [] and out["patterns"] == [] and out["risk_score"] == 100


def test_original_exposed_admin_path_preserved():
    out = sec.analyze({"TELNET.ENABLED": True, "ACL.MGMT_RESTRICTED": False})
    p = next(x for x in out["patterns"] if x["rule_id"] == "AP-EXPOSED-ADMIN")
    assert p["severity"] == "CRITICAL" and p["contributors"] and p["evidence"]["TELNET.ENABLED"] is True


def test_new_attack_paths_need_their_precondition():
    assert not sec.analyze({"AAA.AUTHENTICATION": False})["patterns"]
    out = sec.analyze({"MGMT.INTERNET_EXPOSED": True, "AAA.MFA": False})
    assert "AP-INTERNET-MGMT-WEAK" in {p["rule_id"] for p in out["patterns"]}
    out = sec.analyze({"LOGGING.ENABLED": False, "TELNET.ENABLED": True})
    assert "AP-BLIND-DEVICE" in {p["rule_id"] for p in out["patterns"]}


def test_assumed_default_is_downgraded_one_level():
    flat = {"TELNET.ENABLED": True}
    assert sec.analyze(flat)["anomalies"][0]["severity"] == "HIGH"
    out = sec.analyze(flat, provenance={"TELNET.ENABLED": {"basis": "default"}})
    a = out["anomalies"][0]
    assert a["severity"] == "MEDIUM" and a["basis"] == "assumed"
    out = sec.analyze({"MGMT.INTERNET_EXPOSED": True}, provenance={"MGMT.INTERNET_EXPOSED": {"basis": "default"}})
    assert out["anomalies"][0]["severity"] == "HIGH"       # a guessed default never yields CRITICAL alone


def test_duplicates_with_compliance_are_flagged():
    out = sec.analyze({"TELNET.ENABLED": True, "HTTP.ENABLED": True}, compliance_failed={"TELNET.ENABLED"})
    flags = {a["property"]: a["duplicates_compliance"] for a in out["anomalies"]}
    assert flags == {"TELNET.ENABLED": True, "HTTP.ENABLED": False}


def test_rule_file_validation(tmp_path):
    bad = tmp_path / "r.yaml"
    bad.write_text("signals:\n  - {id: X, type: T, severity: BOGUS, when: {prop: A, is_true: true}}\n")
    with pytest.raises(sec.RuleError):
        sec.load_rules(bad)
    bad.write_text("signals:\n  - {id: X, type: T, severity: HIGH, when: {prop: A}}\n")
    with pytest.raises(sec.RuleError):
        sec.load_rules(bad)
    bad.write_text("signals:\n  - {id: X, type: T, severity: HIGH, when: {prop: A, is_true: true}}\n"
                   "  - {id: X, type: T, severity: HIGH, when: {prop: A, is_true: true}}\n")
    with pytest.raises(sec.RuleError):
        sec.load_rules(bad)


def test_shipped_rules_load_and_condition_ops():
    r = sec.load_rules()
    assert len(r["signals"]) >= 12 and len(r["paths"]) >= 4
    f = {"a": 3, "b": None}
    assert sec.evaluate({"all": [{"prop": "a", "gte": 3}, {"prop": "b", "missing": True}]}, f)
    assert sec.evaluate({"not": {"prop": "a", "eq": 4}}, f)
    assert sec.evaluate({"prop": "a", "in": [1, 3]}, f) and not sec.evaluate({"prop": "a", "lt": 3}, f)
