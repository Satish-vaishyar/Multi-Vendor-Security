"""Unit tests for every remaining uncovered line: engines, registries, KB, CVE helpers."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.engines import eval_op, eval_condition, ComplianceEngine  # noqa: E402
from src.schemas import Control, Finding, Evidence  # noqa: E402
from src.knowledge_extras import (RemediationKB, RiskEngine, MappingRegistry,  # noqa: E402
                                  nest_flat_ir)
from src.schemas import VendorMapping  # noqa: E402
from src.control_kb import ControlKB, FrameworkRegistry, Crosswalk  # noqa: E402
from src.property_registry import PropertyRegistry  # noqa: E402
from src.learning_engine import LearningEngine  # noqa: E402
from src.cve.version_normalizer import normalize, compare  # noqa: E402
from src.cve.kb import VulnKB  # noqa: E402
from src.cve import update as cve_update  # noqa: E402
from src.cve.inventory import extract  # noqa: E402
from src.cve.cbom import classify, build_cbom  # noqa: E402
from src.cve.correlator import correlate, to_findings  # noqa: E402


# ---------------- engines ----------------
def test_eval_op_full():
    assert eval_op("a", "NOT_EQUALS", "b") is True
    assert eval_op("3", "LTE", 3) is True
    assert eval_op("4", "GT", 3) is True
    assert eval_op("2", "LT", 3) is True
    assert eval_op("x", "NOT_IN", ["y"]) is True
    assert eval_op("hello world", "CONTAINS", "world") is True
    assert eval_op("x", "EXISTS", None) is True
    assert eval_op("abc", "GTE", 2) is False  # float() raises -> False
    assert eval_op("a", "BOGUS", "a") is False  # unknown operator falls through


def test_eval_condition_any_branches():
    ir = {"A": {"X": True}, "B": {"Y": False}}
    ok, _ = eval_condition(ir, {"any": [{"property": "A.X", "operator": "EQUALS", "value": True},
                                     {"property": "B.Y", "operator": "EQUALS", "value": True}]})
    assert ok is True
    ok, _ = eval_condition(ir, {"any": [{"property": "B.Y", "operator": "EQUALS", "value": True},
                                     {"property": "A.X", "operator": "EQUALS", "value": False}]})
    assert ok is False


def test_evaluate_empty_condition_and_score():
    c = Control(control_id="T-EMPTY", title="t", condition={"all": []})
    f = ComplianceEngine([c]).evaluate({})[0]
    assert f.status == "PASS"  # vacuous truth, empty evidence list branch
    assert ComplianceEngine.score([])["compliance_score"] == 0.0
    mixed = [
        Finding(finding_id="1", control_id="a", title="t", severity="INFO", status="FAIL",
                evidence=Evidence(control_id="a", property="p")),
        Finding(finding_id="2", control_id="b", title="t", severity="HIGH", status="FAIL",
                evidence=Evidence(control_id="b", property="p")),
        Finding(finding_id="3", control_id="c", title="t", severity="LOW", status="PASS",
                evidence=Evidence(control_id="c", property="p")),
    ]
    sc = ComplianceEngine.score(mixed)
    assert sc["failed"] == 2 and sc["HIGH"] == 1 and sc["passed"] == 1


# ---------------- knowledge extras ----------------
def test_remediation_kb_loads():
    kb = RemediationKB().load()
    assert "OKF-TELNET-001" in kb.index and "cisco" in kb.index["OKF-TELNET-001"]["vendors"]


def test_risk_priorities():
    mk = lambda sev, conf=1.0: Finding(finding_id="x", control_id="c", title="t",
                                       severity=sev, status="FAIL", confidence=conf,
                                       evidence=Evidence(control_id="c", property="p"))
    assert RiskEngine.score_finding(mk("CRITICAL"), "CRITICAL", True)["priority"] == "CRITICAL"
    assert RiskEngine.score_finding(mk("LOW"), "LOW")["priority"] == "LOW"
    assert RiskEngine.score_finding(mk("MEDIUM"), "BOGUS")["priority"] == "MEDIUM"
    floored = RiskEngine.score_finding(mk("HIGH", 0.0), "HIGH")
    assert floored["factors"]["confidence"] == 0.0 and floored["risk_score"] > 0


def test_registry_skip_and_bad_regex(tmp_path):
    reg = MappingRegistry().load()
    out = reg.to_canonical_ir("! comment\n\n   \n# hash\nset system services ssh protocol-version v2\n",
                              vendor="juniper")
    assert out["ir"].get("SSH.VERSION") == 2  # cisco packs skipped via vendor check
    reg.maps.insert(0, VendorMapping(vendor="cisco", platform="x", raw_command_pattern="[",
                                     canonical_property="SSH.VERSION", canonical_value=2))
    out2 = reg.to_canonical_ir("ip ssh version 2", vendor="cisco")
    assert out2["ir"].get("SSH.VERSION") == 2  # bad regex skipped, good rule still wins


def test_registry_learned_dir(tmp_path):
    learned = tmp_path / "learned"
    learned.mkdir()
    (learned / "x.yaml").write_text(
        "mappings:\n- {vendor: tmp, platform: any, raw_command_pattern: 'abc', "
        "canonical_property: SSH.VERSION, canonical_value: 2}\n", encoding="utf-8")
    (tmp_path / "a.yaml").write_text("mappings: []\n", encoding="utf-8")
    reg = MappingRegistry().load(base=tmp_path)
    assert any(m.vendor == "tmp" for m in reg.maps)


def test_registry_approve_existing_file(tmp_path):
    reg = MappingRegistry()
    dest = tmp_path / "l.yaml"
    dest.write_text("{\"mappings\": []}", encoding="utf-8")
    m = reg.approve("v", "p", "pat", "SSH.VERSION", 2, out=dest)
    assert m.source == "human_verified"
    m2 = reg.approve("v", "p", "pat2", "SSH.VERSION", 2, out=dest)
    assert len(reg.maps) == 2 and m2.canonical_value == 2


# ---------------- registries ----------------
def test_framework_registry_and_crosswalk(tmp_path):
    fw = FrameworkRegistry().load()
    assert {"CIS", "NIST", "STIG", "ISO27001", "CERTIN"} <= set(fw.frameworks)
    # corrupt + non-framework files are skipped
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "other.json").write_text('{"a": 1}', encoding="utf-8")
    assert FrameworkRegistry().load(base=tmp_path).frameworks == {}
    ckb = ControlKB().load()
    assert len(ckb.for_frameworks([])) == len(ckb.all())
    assert all("NIST" in c.frameworks for c in ckb.for_frameworks(["nist"]))
    x = Crosswalk().load()
    assert x.for_control("OKF-SSH-001", ckb.controls)["mapped_controls"]
    assert x.for_control("NOPE", ckb.controls) == {"mapped_controls": []}


def test_property_registry(tmp_path):
    pr = PropertyRegistry().load()
    assert len(pr.all()) >= 100 and pr.get("SSH.VERSION").datatype == "enum"
    assert "SSH.VERSION" in pr.ids()
    empty = PropertyRegistry().load(base=tmp_path)
    assert empty.all() == [] and empty.get("X") is None


# ---------------- learning engine ----------------
def test_learning_merge_and_helpers(monkeypatch):
    import src.learning_engine as le
    reg = MappingRegistry().load()
    eng = LearningEngine(reg)
    monkeypatch.setattr(le, "parse_config_to_ir", lambda *a, **k: {
        "mappings": [
            {"canonical_property": "SSH.VERSION", "canonical_value": 1,  # collides -> det wins
             "confidence": 0.9, "evidence": "ip ssh version 2"},
            {"canonical_property": "NTP.ENABLED", "canonical_value": True,
             "confidence": 0.8, "evidence": "mystery line"}]})
    out = eng.audit_config("! comment\n\nip ssh version 2\nmystery line\n", vendor="cisco")
    assert out["flat_ir"]["SSH.VERSION"] == 2 and out["flat_ir"]["NTP.ENABLED"] is True
    assert out["unknown_lines"] == []
    assert nest_flat_ir({"A.B": 1}) == {"A": {"B": 1}}
    monkeypatch.setattr(le, "suggest_mapping", lambda *a, **k: {"ok": True})
    assert eng.suggest("x") == {"ok": True}
    called = {}
    monkeypatch.setattr(reg, "approve", lambda *a, **k: called.setdefault("yes", True))
    eng.approve("v", "p", "pat", "SSH.VERSION", 2)
    assert called.get("yes")


# ---------------- normalizer extras ----------------
def test_normalizer_extra_branches():
    assert normalize("17.9.4a-ES").train == "es"
    assert normalize("blah-blah").suffix == "blah"
    assert normalize("17.9.4a-ES") < normalize("17.9.4a-S")
    assert normalize("17.9.4a") < normalize("17.9.4b")  # suffix lexical branch
    a = normalize("17.9.2")
    assert (a <= normalize("17.9.2")) and (a <= normalize("17.9.3"))
    assert compare("17.9.2", "==", "17.9.2") is True
    assert compare("17.9.2", "!=", "17.9.3") is True
    assert compare("17.9.2", "<=", "17.9.2") is True
    try:
        compare("1", "BOGUS", "1")
        assert False
    except ValueError:
        assert True


# ---------------- kb save/upsert ----------------
def test_kb_save_upsert(tmp_path, monkeypatch):
    import src.cve.kb as kbmod
    store, meta = tmp_path / "c.json", tmp_path / "m.json"
    monkeypatch.setattr(kbmod, "STORE", store)
    monkeypatch.setattr(kbmod, "META", meta)
    kb = VulnKB()
    kb.upsert({"cve_id": "CVE-T-1", "affected": [{"vendor": "v", "product": "p",
                "affected_versions": []}]})
    kb.upsert({"cve_id": "CVE-T-1", "affected": []})  # replace existing
    kb.save()
    assert store.exists() and meta.exists()
    kb2 = VulnKB().load()
    assert kb2.records[0]["affected"] == [] and kb2.candidates("v", "p") == []


# ---------------- update.sync_now ----------------
def test_sync_now_paths(monkeypatch):
    import src.cve.nvd_client as nvd
    monkeypatch.setattr(nvd, "sync", lambda *a, **k: {"added": 2, "total": 7})
    assert cve_update.sync_now()["ok"] is True

    def _raise(*a, **k):
        raise ConnectionError("down")
    monkeypatch.setattr(nvd, "sync", _raise)
    assert cve_update.sync_now()["ok"] is False


def test_assets_affected_unknown():
    rec = {"cve_id": "X", "affected": [{"vendor": "cisco", "product": "ios_xe",
                                        "affected_versions": []}]}
    out = cve_update.assets_affected(rec, [
        {"asset_id": "U1", "vendor": "nope", "product": "nope", "version": "1"},
        {"asset_id": "U2", "vendor": "cisco", "product": "ios_xe", "version": ""}])
    assert all(a["status"] == "UNKNOWN" for a in out["assets"])


# ---------------- inventory + cbom ----------------
def test_inventory_extract():
    cfg = ("Cisco IOS-XE version 17.9.2\njunos: 22.4R3\nversion 17.9.2\n"
           "Cisco IOS-XE version 17.9.2\nssh server enable\n")
    comps = extract(cfg, default_vendor="cisco")
    kinds = {(c["vendor"], c["product"]) for c in comps}
    assert ("cisco", "ios-xe") in kinds and ("juniper", "junos") in kinds
    # A bare "ssh" keyword is NOT evidence of OpenBSD OpenSSH (e.g. Cisco IOS
    # implements SSH inside the OS) — it must not fabricate an unversioned
    # component that can never correlate.
    assert ("openbsd", "openssh") not in kinds
    # ...but a real OpenSSH banner carrying a version is picked up.
    banner = {(c["vendor"], c["product"], c["version"])
              for c in extract("SSH-2.0-OpenSSH_8.9p1 Debian-3", default_vendor="cisco")}
    assert ("openbsd", "openssh", "8.9p1") in banner
    assert sum(1 for c in comps if c["version"] == "17.9.2" and c["product"] == "ios-xe") == 1
    assert extract("nothing here", default_vendor="cisco") == []


def test_cbom_classify_and_build():
    assert classify("ml-kem") == "pqc-ready"
    assert classify("x25519-kyber") == "hybrid"
    assert classify("des") == "deprecated"
    assert classify("") == "unknown"
    assert classify("rsa-2048") == "classical"
    rows = build_cbom("A", [{"vendor": "v", "product": "p", "version": "1",
                             "component_type": "operating_system"}],
                      {"CRYPTO.WEAK_ALGO": True, "OTHER.X": False})
    assert len(rows) == 2 and rows[1]["klass"] == "deprecated"
    assert build_cbom("A", [], None) == []


# ---------------- correlator scoping + findings ----------------
def test_correlator_product_scoping():
    kb = VulnKB()
    kb.records = [{
        "cve_id": "CVE-T-9", "cvss": {}, "references": [],
        "affected": [
            {"vendor": "cisco", "product": "ios_xe", "cpe": "cpe:2.3:o:cisco:ios_xe:*:*",
             "affected_versions": [{"start": "17.0", "start_inclusive": True,
                                    "end": "17.9.9", "end_inclusive": True}]},
            {"vendor": "CiscoSystems", "product": "other", "cpe": "cpe:2.3:o:cisco:other:*:*",
             "affected_versions": [{"start": "1.0", "start_inclusive": True,
                                    "end": "99.0", "end_inclusive": True}]},
            {"vendor": "juniper", "product": "junos", "cpe": "cpe:2.3:o:juniper:junos:*:*",
             "affected_versions": [{"start": "1.0", "start_inclusive": True,
                                    "end": "99.0", "end_inclusive": True}]},
        ]}]
    kb._index()
    corr = correlate([{"vendor": "Cisco", "product": "IOS-XE", "version": "17.9.2",
                       "component_type": "operating_system"}], asset_id="R", kb=kb)
    # strict product scoping: only the ios_xe entry matches; same-vendor
    # "other" and juniper entries must NOT leak in (that exploded real NVD
    # KBs into millions of false rows).
    assert corr["summary"]["vulnerable"] == 1
    assert [m["cve_id"] for m in corr["matches"]] == ["CVE-T-9"]


def test_correlator_dedupe_and_exact_version():
    from src.cve.version_normalizer import normalize as _norm
    # NVD CPE escapes must compare equal to plain installed versions.
    assert _norm("12.0\\(32\\)S12") == _norm("12.0(32)s12")
    kb = VulnKB()
    kb.records = [{
        "cve_id": "CVE-T-10", "cvss": {"severity": "HIGH"}, "references": [],
        "affected": [
            {"vendor": "cisco", "product": "ios_xe", "cpe": "cpe:2.3:o:cisco:ios_xe:17.9.2:*:*",
             "affected_versions": [{"start": "17.9.2", "start_inclusive": True,
                                    "end": "17.9.2", "end_inclusive": True}]},
            {"vendor": "cisco", "product": "ios_xe", "cpe": "cpe:2.3:o:cisco:ios_xe:17.9.3:*:*",
             "affected_versions": [{"start": "17.9.3", "start_inclusive": True,
                                    "end": "17.9.3", "end_inclusive": True}]},
        ]}]
    kb._index()
    comp = {"vendor": "cisco", "product": "ios_xe", "component_type": "operating_system"}
    hit = correlate([{**comp, "version": "17.9.2"}], kb=kb)
    assert len(hit["matches"]) == 1 and hit["matches"][0]["status"] == "VULNERABLE"
    miss = correlate([{**comp, "version": "17.9.5"}], kb=kb)
    assert len(miss["matches"]) == 1 and miss["matches"][0]["status"] == "NOT_AFFECTED"


def test_miss_carries_own_product_range():
    # Regression: CVE-2010-2830-style multi-product record showed IOS 12.2's
    # range on an ios-xe assessment because misses stored matched_rule=None
    # and the detail layer backfilled the CVE's first (other-product) entry.
    from src.cve.version_range import match_record as _mr
    assert _mr("17.9.2", [{"start": "2.5.0", "end": "2.5.0"}])["matched_rule"] == \
        {"start": "2.5.0", "end": "2.5.0"}
    kb = VulnKB()
    kb.records = [{
        "cve_id": "CVE-T-11", "cvss": {"severity": "HIGH"}, "references": [],
        "affected": [
            {"vendor": "cisco", "product": "ios", "cpe": "cpe:2.3:o:cisco:ios:12.2:*:*",
             "affected_versions": [{"start": "12.2", "start_inclusive": True,
                                    "end": "12.2", "end_inclusive": True}]},
            {"vendor": "cisco", "product": "ios_xe", "cpe": "cpe:2.3:o:cisco:ios_xe:2.5.0:*:*",
             "affected_versions": [{"start": "2.5.0", "start_inclusive": True,
                                    "end": "2.5.0", "end_inclusive": True}]},
        ]}]
    kb._index()
    corr = correlate([{"vendor": "cisco", "product": "ios_xe", "version": "17.9.2",
                       "component_type": "operating_system"}], kb=kb)
    assert len(corr["matches"]) == 1
    m = corr["matches"][0]
    assert m["status"] == "NOT_AFFECTED"
    assert (m["matched_rule"] or {}).get("start") == "2.5.0"  # own product, not 12.2
    assert m["installed_cpe"] == "cpe:2.3:o:cisco:ios_xe:17.9.2:*:*:*:*:*:*:*"


def test_to_findings_branches():
    corr = {"matches": [
        {"cve_id": "CVE-A", "product": "p", "installed_version": "1", "status": "VULNERABLE",
         "cvss": {"severity": "WEIRD"}, "fixed_version": "2",
         "evidence": {}, "references": []},
        {"cve_id": "CVE-B", "product": "p", "installed_version": "1", "status": "VULNERABLE",
         "cvss": {}, "fixed_version": None, "evidence": {}, "references": []},
        {"cve_id": "CVE-C", "product": "p", "installed_version": "1", "status": "VULNERABLE",
         "cvss": {"severity": "MEDIUM"}, "fixed_version": None, "evidence": {}, "references": []},
        {"cve_id": "CVE-D", "product": "p", "installed_version": "9", "status": "NOT_AFFECTED",
         "cvss": {}, "fixed_version": None, "evidence": {}, "references": []},
    ]}
    out = to_findings(corr, "A")
    assert [f["severity"] for f in out] == ["HIGH", "HIGH", "MEDIUM"]
    assert out[0]["remediation"]["fixed_version"] == "2"
    assert "advisory" in out[1]["remediation"]["recommendation"]
