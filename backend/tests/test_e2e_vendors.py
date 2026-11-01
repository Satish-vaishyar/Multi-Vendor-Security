"""End-to-end: upload -> detect -> parse -> audit -> results, for every vendor in the authored corpus."""
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core import config as cfg
from app.main import app

client = TestClient(app)
CORPUS = Path(cfg.OKF_DIR) / "tests" / "corpus"

# file -> (vendor, platform, expected control verdicts (status), min assessed-coverage %)
CASES = {
    "cisco_iosxe_core_hardened.cfg": ("CISCO", "IOS-XE", {
        "OKF-TELNET-001": "PASS", "OKF-HTTP-001": "PASS", "OKF-SSH-001": "PASS", "OKF-SNMP-001": "PASS",
        "OKF-AAA-002": "PASS", "OKF-PASS-002": "PASS", "OKF-ACL-002": "PASS", "OKF-SWITCH-001": "NOT_APPLICABLE"}, 90),
    "cisco_iosxe_branch_insecure.cfg": ("CISCO", "IOS-XE", {
        "OKF-TELNET-001": "FAIL", "OKF-HTTP-001": "FAIL", "OKF-SNMP-001": "FAIL", "OKF-SNMP-004": "FAIL",
        "OKF-ACL-002": "FAIL", "OKF-PASS-002": "FAIL", "OKF-USER-001": "FAIL", "OKF-SSH-001": "PASS"}, 90),
    "cisco_nxos_dc_switch.cfg": ("CISCO", "NX-OS", {
        "OKF-TELNET-001": "FAIL", "OKF-SNMP-001": "FAIL", "OKF-PASS-003": "NOT_APPLICABLE",
        "OKF-SVC-001": "NOT_APPLICABLE", "OKF-SSH-001": "PASS"}, 85),
    "arista_eos_leaf.cfg": ("ARISTA", "EOS", {
        "OKF-TELNET-001": "PASS", "OKF-HTTP-001": "PASS", "OKF-SSH-001": "PASS", "OKF-AAA-002": "PASS",
        "OKF-PASS-003": "NOT_APPLICABLE"}, 85),
    "junos_ex_access_mixed.cfg": ("JUNIPER", "Junos", {
        "OKF-TELNET-001": "FAIL", "OKF-SSH-001": "PASS", "OKF-SNMP-001": "FAIL", "OKF-AAA-002": "PASS",
        "OKF-PASS-003": "NOT_APPLICABLE", "OKF-SWITCH-001": "PASS"}, 85),
    "junos_srx_edge_set.cfg": ("JUNIPER", "Junos", {
        "OKF-TELNET-001": "PASS", "OKF-HTTP-001": "FAIL", "OKF-ACL-002": "FAIL",
        "OKF-SWITCH-001": "NOT_APPLICABLE"}, 85),
    "fortios_fg100f_edge.cfg": ("FORTINET", "FortiOS", {
        "OKF-TELNET-001": "PASS", "OKF-HTTP-001": "FAIL", "OKF-ACL-002": "FAIL", "OKF-USER-001": "FAIL",
        "OKF-SSH-002": "FAIL", "OKF-PASS-003": "NOT_APPLICABLE", "OKF-SWITCH-001": "NOT_APPLICABLE"}, 80),
    "panos_pa850_set.cfg": ("PALOALTO", "PAN-OS", {
        "OKF-TELNET-001": "PASS", "OKF-HTTP-001": "FAIL", "OKF-ACL-002": "FAIL", "OKF-AAA-002": "PASS",
        "OKF-PASS-003": "NOT_APPLICABLE"}, 80),
}


def _audit(name: str):
    text = (CORPUS / name).read_bytes()
    asset = client.post("/api/v1/assets", json={"name": f"e2e-{uuid.uuid4().hex[:6]}"}).json()["data"]["asset_id"]
    up = client.post("/api/v1/configurations/upload", data={"asset_id": asset},
                     files={"file": (name, text, "text/plain")})
    assert up.status_code == 200, up.text
    cid = up.json()["data"]["configuration_id"]
    r = client.post("/api/v1/audits", json={"asset_id": asset, "configuration_id": cid, "run_cve": False,
                                            "frameworks": ["CIS", "NIST", "STIG", "ISO27001", "CERTIN"]})
    assert r.status_code == 200, r.text
    aid = r.json()["data"]["audit_id"]
    return up.json()["data"], client.get(f"/api/v1/audits/{aid}/results").json()["data"]


@pytest.mark.parametrize("name", sorted(CASES))
def test_vendor_end_to_end(name):
    vendor, platform, verdicts, min_cov = CASES[name]
    upload, res = _audit(name)
    assert upload["detected_vendor"] == vendor and upload["detected_platform"] == platform
    a = res["assessment"]
    assert a["parser"]["used"] is True
    assert a["coverage_pct"] >= min_cov, f"{name}: only {a['coverage_pct']}% of applicable controls assessed"
    assert a["assessed"] + a["not_assessed"] == a["applicable"]
    assert a["assumed"] <= a["assessed"]
    by_ctrl = {f["control_id"]: f for f in res["findings"] if f.get("engine") == "compliance"}
    wrong = {c: (by_ctrl[c]["status"], want) for c, want in verdicts.items() if by_ctrl[c]["status"] != want}
    assert not wrong, f"{name}: (got, wanted) {wrong}"
    # a FAIL carries evidence whose line really exists in the uploaded config
    text_lines = [l.strip() for l in (CORPUS / name).read_text(encoding="utf-8").splitlines()]
    fails = [f for f in by_ctrl.values() if f["status"] == "FAIL" and (f.get("evidence") or {}).get("basis") == "config"]
    if "hardened" not in name:   # a hardened device may legitimately have no observed-line failure
        assert fails, "expected at least one FAIL backed by an observed config line"
    ev = client.get(f"/api/v1/audits/{res['audit_id']}/evidence").json()["data"]["items"]
    with_line = [e for e in ev if e["source"]["line"]]
    assert with_line, "evidence must reference config lines"
    for e in with_line:
        assert e["source"]["line"] in text_lines or "<REDACTED>" in e["source"]["line"], e


def test_assumed_defaults_are_labelled_in_findings():
    _, res = _audit("junos_ex_access_mixed.cfg")
    comp = [f for f in res["findings"] if f.get("engine") == "compliance"]
    bases = {(f.get("evidence") or {}).get("basis") for f in comp}
    assert {"config", "default"} <= bases
    for f in comp:
        ev = f.get("evidence") or {}
        if ev.get("basis") == "default":
            assert ev.get("note"), f"{f['control_id']}: assumed verdict without an explanation"
    assert res["assessment"]["assumed"] > 0 and res["assessment"]["observed_pct"] < res["assessment"]["coverage_pct"]


def test_hardened_scores_far_above_insecure():
    _, good = _audit("cisco_iosxe_core_hardened.cfg")
    _, bad = _audit("cisco_iosxe_branch_insecure.cfg")
    assert good["summary"]["compliance_score"] >= 90
    assert bad["summary"]["compliance_score"] <= 45
    assert good["summary"]["critical"] < bad["summary"]["critical"]


def test_unknown_vendor_still_routes_to_the_learning_loop():
    text = b"blorp zeta-protocol enable\nfrobnicate level 9\n"
    asset = client.post("/api/v1/assets", json={"name": f"unk-{uuid.uuid4().hex[:6]}"}).json()["data"]["asset_id"]
    cid = client.post("/api/v1/configurations/upload", data={"asset_id": asset},
                      files={"file": ("x.txt", text, "text/plain")}).json()["data"]["configuration_id"]
    r = client.post("/api/v1/audits", json={"asset_id": asset, "configuration_id": cid, "run_cve": False})
    assert r.status_code == 200
    res = client.get(f"/api/v1/audits/{r.json()['data']['audit_id']}/results").json()["data"]
    assert res["assessment"]["parser"]["used"] is False       # no structured parser for an unknown vendor
    assert res["assessment"]["coverage_pct"] is not None      # and the audit still completes, never hard-fails


def test_pdf_report_states_coverage_and_assumed_defaults(monkeypatch):
    """The auditor-facing PDF must disclose what was not assessed and what rests on assumptions."""
    from reportlab import rl_config
    monkeypatch.setattr(rl_config, "pageCompression", 0)       # uncompressed streams so the text is greppable
    _, res = _audit("junos_ex_access_mixed.cfg")
    rep = client.post("/api/v1/reports", json={"audit_id": res["audit_id"], "format": "PDF"})
    assert rep.status_code == 200, rep.text
    pdf = client.get(f"/api/v1/reports/{rep.json()['data']['report_id']}/download").content
    assert pdf.startswith(b"%PDF")
    blob = pdf.replace(b"\n", b" ")
    assert b"Assessment" in blob and b"coverage" in blob
    assert b"assumed" in blob and b"not assessed" in blob.lower()


def test_validator_failure_is_not_reported_as_valid(monkeypatch):
    """P1-3: a broken validator used to return valid=True. It must fail closed and mark the audit degraded."""
    from app.services import integration
    integration._ensure_bridge()
    import src.m5_validator as m5

    def boom(_flat):
        raise RuntimeError("validator artifact missing")

    monkeypatch.setattr(m5, "validate", boom)
    _, res = _audit("cisco_iosxe_core_hardened.cfg")
    assert res["ir_validation"]["valid"] is False and res["ir_validation"]["validator_error"] is True
    assert any("IR validator unavailable" in x for x in res["degraded"])


def test_extractor_failure_keeps_other_facts_and_is_reported(monkeypatch):
    from app.services import integration
    integration._ensure_bridge()
    from src.vendor_parsers import ioslike

    def boom(self):
        raise ValueError("unexpected syntax")

    monkeypatch.setattr(ioslike.IosLike, "_snmp", boom)
    _, res = _audit("cisco_iosxe_core_hardened.cfg")
    assert any("unexpected syntax" in x for x in res["degraded"])
    by_ctrl = {f["control_id"]: f for f in res["findings"] if f.get("engine") == "compliance"}
    assert by_ctrl["OKF-TELNET-001"]["status"] == "PASS"          # unaffected extractors still produced facts
    assert by_ctrl["OKF-SNMP-001"]["status"] in ("UNKNOWN", "PASS")   # the failed area is not reported as a failure


def test_healthy_audit_is_not_degraded():
    _, res = _audit("junos_srx_edge_set.cfg")
    assert res["degraded"] == []
