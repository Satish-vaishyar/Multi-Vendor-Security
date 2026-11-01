"""Fix library + composer: template integrity, coverage, and context-aware plans from real corpus configs."""
import re
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from app.core import config as cfg
from app.main import app
from app.services import integration

integration._ensure_bridge()
from src import vendor_parsers  # noqa: E402
from src.knowledge_extras import nest_flat_ir  # noqa: E402
from src.remediation_gen import FIX_DIR, FixLibrary  # noqa: E402

okf = integration.okf_layer()
LIB: FixLibrary = okf["fixlib"]
CORPUS = Path(cfg.OKF_DIR) / "tests" / "corpus"
FILES = sorted(FIX_DIR.glob("*.yaml"))
PARAM_RE = re.compile(r"<([A-Z][A-Z0-9_]{1,40})>")
VENDOR_PLATFORM = {"cisco": "ios-xe", "arista": "eos", "juniper": "junos", "fortinet": "fortios", "paloalto": "pan-os"}
KNOWN_PROPS = {p.property_id for p in okf["props"].all()}


# ------------------------------------------------------------------ template integrity
@pytest.mark.parametrize("path", FILES, ids=lambda p: p.stem)
def test_templates_are_well_formed(path):
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["vendor"] in VENDOR_PLATFORM and data["verification"] in ("documented", "lab-verified")
    assert data.get("sources"), "every library must cite the documentation it was written from"
    assert data.get("apply_notes")
    fixes, params = data["fixes"], data.get("parameters", {})
    problems = []
    for prop, fix in fixes.items():
        if prop not in KNOWN_PROPS:
            problems.append(f"{prop}: unknown canonical property")
        if not fix.get("title"):
            problems.append(f"{prop}: no title")
        cmds = (fix.get("setup") or []) + (fix.get("commands") or [])
        if not cmds and not fix.get("includes"):
            problems.append(f"{prop}: no commands")
        for inc in fix.get("includes") or []:
            if inc not in fixes:
                problems.append(f"{prop}: includes unknown fix {inc}")
        if not fix.get("per_target") and any("{name}" in c for c in cmds + (fix.get("rollback") or [])):
            problems.append(f"{prop}: uses {{name}} but is not per_target")
        if cmds and not fix.get("validation") and not fix.get("manual"):
            problems.append(f"{prop}: no validation command")
        if cmds and "rollback" not in fix and not fix.get("includes"):
            problems.append(f"{prop}: rollback not stated (use [] when none exists)")
        if cmds and fix.get("disruption") not in ("low", "medium", "high"):
            problems.append(f"{prop}: disruption must be low|medium|high")
        if fix.get("disruption") == "high" and not (fix.get("impact") or fix.get("prerequisites")):
            problems.append(f"{prop}: high-disruption fix without impact/prerequisites")
        for text in cmds + (fix.get("rollback") or []) + (fix.get("validation") or []):
            for p in PARAM_RE.findall(text):
                if p not in params and p not in ("TARGET",):
                    problems.append(f"{prop}: placeholder <{p}> is not described under `parameters`")
    assert not problems, f"{path.name}:\n  " + "\n  ".join(problems)


def test_no_hard_coded_addresses_in_commands():
    """Commands must use <PLACEHOLDERS>, never a literal address (descriptions may give examples)."""
    ip = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    allowed = {"0.0.0.0", "255.255.255.255", "0.0.0.0/0"}
    for path in FILES:
        for prop, fix in yaml.safe_load(path.read_text(encoding="utf-8"))["fixes"].items():
            for text in (fix.get("setup") or []) + (fix.get("commands") or []) + (fix.get("rollback") or []):
                bad = [m for m in ip.findall(text) if m not in allowed]
                assert not bad, f"{path.name}:{prop}: literal address {bad} in {text!r}"


# ------------------------------------------------------------------------------ coverage
def test_coverage_per_vendor():
    controls = okf["ckb"].all()
    got = {}
    for vendor, plat in VENDOR_PLATFORM.items():
        c = LIB.coverage(controls, vendor, plat)
        got[vendor] = c["fixable"]
    # thresholds sit just under the measured values so a regression (deleted template) is caught
    assert got["cisco"] >= 75, got
    # Many controls are platform-irrelevant on firewalls (IOS-only / switch-only), so absolute counts differ by vendor.
    assert got["juniper"] >= 65 and got["arista"] >= 57 and got["fortinet"] >= 60 and got["paloalto"] >= 47, got
    assert LIB.coverage(controls, "cisco", "nx-os")["fixable"] == 0       # no NX-OS templates: no wrong-syntax plans
    assert LIB.plan(controls[0], {}, {}, "cisco", "nx-os") is None


# ------------------------------------------------------------------------- composition
def _fail_plans(corpus_file: str, vendor: str, platform: str):
    text = (CORPUS / corpus_file).read_text(encoding="utf-8")
    res = vendor_parsers.parse(text, vendor, platform)
    ir = nest_flat_ir(res.flat)
    ce = okf["ComplianceEngine"](okf["ckb"].all(), {})
    plans = {}
    for fnd in ce.evaluate(ir, vendor=vendor, platform=platform, not_applicable=res.not_applicable, provenance=res.provenance):
        if fnd.status == "FAIL":
            control = okf["ckb"].controls[fnd.control_id]
            plans[fnd.control_id] = LIB.plan(control, ir, res.provenance, vendor, platform)
    return plans


def _text(plan):
    return "\n".join(s["command"] for s in plan["steps"])


def test_ios_plan_names_the_real_vty_lines_snmp_communities_and_bgp_neighbor():
    plans = _fail_plans("cisco_iosxe_branch_insecure.cfg", "cisco", "ios-xe")
    telnet = _text(plans["OKF-TELNET-001"])
    assert "line vty 0 4" in telnet and "transport input ssh" in telnet
    assert "line vty 5 15" not in telnet                              # that block is already ssh-only
    snmp = _text(plans["OKF-SNMP-001"])
    assert "no snmp-server community public" in snmp and "no snmp-server community private" in snmp
    assert "mgmt-ro" not in snmp
    assert "no snmp-server community private" in _text(plans["OKF-SNMP-004"])
    # restricting a read-write community must keep it read-write
    acl = _text(plans["OKF-SNMP-005"])
    assert "snmp-server community private RW SNMP-NMS" in acl and "snmp-server community public RO SNMP-NMS" in acl
    assert "router bgp 65014" in _text(plans["OKF-RTG-001"]) and "neighbor 10.99.0.2 password" in _text(plans["OKF-RTG-001"])
    assert "no username admin" in _text(plans["OKF-USER-001"])
    redirects = _text(plans["OKF-IP-002"])
    assert "interface GigabitEthernet0/0/0" in redirects and "interface GigabitEthernet0/0/2" in redirects
    assert "interface GigabitEthernet0/0/1" not in redirects.split("no ip proxy-arp")[0] or "no ip redirects" in redirects


def test_fortios_plan_edits_only_the_offending_interface_and_keeps_other_access():
    plans = _fail_plans("fortios_fg100f_edge.cfg", "fortinet", "fortios")
    http = _text(plans["OKF-HTTP-001"])
    assert 'edit "wan1"' in http and "set allowaccess ping https ssh" in http
    assert "set allowaccess ping https ssh http" not in http                 # http really removed
    assert 'edit "lan"' not in http                                          # lan never had http
    p = plans["OKF-HTTP-001"]
    assert any("allowaccess ping https ssh http" in r for r in p["rollback"]) # rollback restores the original list
    assert 'edit "admin"' in _text(plans["OKF-NIST-AC3"]) or 'edit "admin"' in _text(plans["OKF-ACL-001"])


def test_junos_and_panos_plans_use_real_objects():
    junos = _fail_plans("junos_ex_access_mixed.cfg", "juniper", "junos")
    assert "delete system services telnet" in _text(junos["OKF-TELNET-001"])
    assert "delete snmp community public" in _text(junos["OKF-SNMP-001"])
    assert "delete system login user admin" in _text(junos["OKF-USER-001"])
    pan = _fail_plans("panos_pa850_set.cfg", "paloalto", "pan-os")
    assert "temp-allow-all" in _text(pan["OKF-ACL-002"])
    http = _text(pan["OKF-HTTP-001"])
    assert "disable-http yes" in http and "interface-management-profile MGMT-ADMIN http no" in http


def test_any_condition_picks_the_least_disruptive_alternative():
    plans = _fail_plans("cisco_iosxe_branch_insecure.cfg", "cisco", "ios-xe")
    snmp3 = _text(plans["OKF-SNMP-002"])          # (SNMP disabled) OR (SNMPv3): the v3 route, not "no snmp-server"
    assert "snmp-server user" in snmp3 and "no snmp-server\n" not in snmp3 + "\n"


def test_plan_metadata_is_complete_and_honest():
    p = _fail_plans("cisco_iosxe_branch_insecure.cfg", "cisco", "ios-xe")["OKF-TELNET-001"]
    assert p["verification"] == "documented" and "not tested on a lab device" in p["verification_note"]
    assert p["impact"] and p["prerequisites"] and p["validation"] and p["rollback"] and p["sources"]
    assert p["apply_notes"] and p["source"] == "fix-library"
    acl = _fail_plans("cisco_iosxe_branch_insecure.cfg", "cisco", "ios-xe")["OKF-ACL-001"]
    assert {x["name"] for x in acl["parameters"]} >= {"MGMT_SUBNET", "WILDCARD"}
    assert all(x["description"] for x in acl["parameters"])
    assert "ACL.PERMIT_ANY" in " ".join(
        s["property"] for s in _fail_plans("cisco_iosxe_branch_insecure.cfg", "cisco", "ios-xe")["OKF-ACL-002"]["sections"])
    manual = _fail_plans("cisco_iosxe_branch_insecure.cfg", "cisco", "ios-xe")["OKF-ACL-002"]
    assert "ACL.PERMIT_ANY" in manual["manual_steps"]


def test_no_plan_when_nothing_is_unmet():
    text = (CORPUS / "cisco_iosxe_core_hardened.cfg").read_text(encoding="utf-8")
    res = vendor_parsers.parse(text, "cisco", "ios-xe")
    ir = nest_flat_ir(res.flat)
    telnet = okf["ckb"].controls["OKF-TELNET-001"]
    assert LIB.plan(telnet, ir, res.provenance, "cisco", "ios-xe") is None


def test_every_vendor_plan_uses_that_vendors_syntax():
    """Guard against cross-vendor leakage: Cisco-only keywords must never appear in other vendors' plans."""
    cisco_only = re.compile(r"^(line vty|snmp-server community|ip http server|aaa new-model)", re.M)
    for fname, vendor, plat in (("junos_ex_access_mixed.cfg", "juniper", "junos"), ("panos_pa850_set.cfg", "paloalto", "pan-os"),
                                ("fortios_fg100f_edge.cfg", "fortinet", "fortios")):
        for cid, plan in _fail_plans(fname, vendor, plat).items():
            if plan:
                assert not cisco_only.search(_text(plan)), f"{vendor} plan for {cid} contains Cisco syntax"


# --------------------------------------------------------------------------------- API
client = TestClient(app)


def test_api_returns_context_aware_plan_and_never_another_vendors_commands():
    import uuid
    asset = client.post("/api/v1/assets", json={"name": f"rem-{uuid.uuid4().hex[:6]}"}).json()["data"]["asset_id"]
    text = (CORPUS / "fortios_fg100f_edge.cfg").read_bytes()
    cid = client.post("/api/v1/configurations/upload", data={"asset_id": asset},
                      files={"file": ("fg.cfg", text, "text/plain")}).json()["data"]["configuration_id"]
    aud = client.post("/api/v1/audits", json={"asset_id": asset, "configuration_id": cid, "run_cve": False}).json()["data"]["audit_id"]
    findings = client.get(f"/api/v1/audits/{aud}/results").json()["data"]["findings"]
    http = next(f for f in findings if f.get("control_id") == "OKF-HTTP-001")
    assert http["status"] == "FAIL"
    plan = client.get(f"/api/v1/remediation/{http['finding_id']}").json()["data"]
    assert plan["source"] == "fix-library" and plan["vendor"] == "fortinet"
    cmds = "\n".join(s["command"] for s in plan["steps"])
    assert 'edit "wan1"' in cmds and "config system interface" in cmds
    assert plan["verification"] == "documented" and plan["impact"] and plan["rollback"] and plan["validation"]
    assert all("section" in s for s in plan["steps"])
    # a finding whose control has no template for this vendor falls back, but still never to a Cisco pack
    other = next((f for f in findings if f.get("engine") == "compliance" and f["status"] == "FAIL"
                  and f["control_id"] not in ("OKF-HTTP-001",)), None)
    if other:
        txt = "\n".join(s["command"] for s in client.get(f"/api/v1/remediation/{other['finding_id']}").json()["data"]["steps"])
        assert "transport input ssh" not in txt and "no ip http server" not in txt


def test_non_default_snmp_community_is_referenced_never_stored():
    """A community string is a credential: provenance/targets/plans carry a line reference, not the value."""
    cfg_text = "hostname R1\nsnmp-server community Zr7!secretString RW\nsnmp-server community Qw3rty-ro RO\n"
    res = vendor_parsers.parse(cfg_text, "cisco", "ios-xe")
    from app.services.audit_service import _redact_provenance        # what is actually persisted with the audit
    blob = repr(_redact_provenance(res.provenance))
    assert "Zr7!secretString" not in blob and "Qw3rty-ro" not in blob
    ir = nest_flat_ir(res.flat)
    plan = LIB.plan(okf["ckb"].controls["OKF-SNMP-004"], ir, res.provenance, "cisco", "ios-xe")
    text = _text(plan)
    assert "Zr7!secretString" not in text and "<COMMUNITY_L2>" in text
    assert any(x["name"] == "COMMUNITY_L2" and "line 2" in x["description"] for x in plan["parameters"])
