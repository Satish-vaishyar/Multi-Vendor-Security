"""End-to-end OKF demo: insecure Cisco config -> audit -> training loop -> re-audit."""
import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.property_registry import PropertyRegistry
from src.control_kb import ControlKB, Crosswalk
from src.engines import ComplianceEngine
from src.knowledge_extras import MappingRegistry, RemediationKB, RiskEngine
from src.learning_engine import LearningEngine
from src.cve.inventory import extract as extract_inventory
from src.cve.correlator import correlate, to_findings
from src.cve.cbom import build_cbom
from src.cve.update import assets_affected
from src.cve.kb import VulnKB

CONFIG = """hostname Core-Router-01
ip ssh version 1
ip http server
transport input telnet
snmp-server community public RO
no logging
ntp server 10.0.0.5
line vty 0 4
 transport input telnet
"""

def main():
    props = PropertyRegistry().load()
    ckb = ControlKB().load()
    rem = RemediationKB().load()
    maps = MappingRegistry().load()
    learn = LearningEngine(maps)
    parsed = learn.audit_config(CONFIG, vendor="cisco")
    eng = ComplianceEngine(ckb.all(), dict(rem.index))
    findings = eng.evaluate(parsed["nested_ir"])
    score = ComplianceEngine.score(findings)
    print(f"Properties: {len(props.all())} | Controls: {len(ckb.all())}")
    print(f"Compliance score: {score['compliance_score']}  FAIL: {score['failed']} PASS: {score['passed']} UNKNOWN: {score['unknown']}")
    for f in findings:
        if f.status == "FAIL":
            print(f"  FAIL {f.control_id} [{f.severity}] {f.title} | observed={f.evidence.observed_value}")
    print(f"Unknown lines: {parsed['unknown_lines']}")
    # training loop demo
    if parsed["unknown_lines"]:
        s = learn.suggest(parsed["unknown_lines"][0], vendor="cisco")
        print("Suggest:", json.dumps(s, indent=1)[:600])
    print("Crosswalk OKF-SSH-001:", Crosswalk().load().for_control("OKF-SSH-001", ckb.controls))
    # ---- CVE side ----
    inv = extract_inventory("Cisco IOS-XE version 17.9.2\n" + CONFIG, default_vendor="cisco")
    corr = correlate(inv, asset_id="RTR-001")
    print(f"CVE: components={len(corr['components'])} summary={corr['summary']}")
    for f in to_findings(corr, "RTR-001"):
        print(f"  {f['severity']} {f['cve_id']} -> {f['remediation']['recommendation']}")
    print(f"CBOM rows: {len(build_cbom('RTR-001', corr['components'], parsed['flat_ir']))}")
    kb = VulnKB().load()
    seed = next(r for r in kb.records if r["cve_id"] == "CVE-2024-99904")
    blast = assets_affected(seed, [
        {"asset_id": "FW-001", "vendor": "fortinet", "product": "fortios", "version": "7.2.2"},
        {"asset_id": "FW-003", "vendor": "fortinet", "product": "fortios", "version": "7.4.0"}])
    print("Blast radius CVE-2024-99904:", [(a["asset_id"], a["status"]) for a in blast["assets"]])

if __name__ == "__main__":
    main()
