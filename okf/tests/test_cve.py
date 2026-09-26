"""CVE engine tests: normalizer, ranges, CPE, correlator + golden set (CVE-11)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.cve.version_normalizer import normalize, compare
from src.cve.version_range import in_range, match_record
from src.cve.cpe_resolver import resolve
from src.cve.kb import VulnKB
from src.cve.correlator import correlate
from src.cve.update import assets_affected


def test_normalizer_formats():
    assert normalize("v7.2.1").nums == (7, 2, 1)
    assert normalize("R81.10").nums == (81, 10)
    assert normalize("22.4R3").nums == (22, 4, 3)
    assert normalize("17.9.4a").suffix == "a"
    assert normalize("7.2(1)").nums == (7, 2, 1)
    assert compare("17.9.4", ">=", "17.0")
    assert compare("10.5", "<", "10.5") is False
    assert compare("22.4R3", ">", "22.4R2")


def test_range_bounds():
    assert in_range("10.4", "10.0", True, "10.5", False) is True
    assert in_range("10.5", "10.0", True, "10.5", False) is False  # exclusive end
    assert in_range("17.9.4", "17.0", True, "17.9.4", True) is True  # inclusive end
    assert in_range("16.9", "17.0", True, "17.9.4", True) is False
    assert in_range("", "17.0", True, "17.9.4", True) is None


def test_cpe_resolver():
    c = resolve("cisco", "ios-xe", "17.9.2")[0]
    assert "cisco" in c and "ios_xe" in c and "17.9.2" in c


def test_correlator_seed():
    kb = VulnKB().load()
    corr = correlate([{"vendor": "cisco", "product": "ios_xe", "version": "17.9.2",
                       "component_type": "operating_system"}], asset_id="RTR-1", kb=kb)
    assert corr["summary"]["vulnerable"] >= 1
    corr2 = correlate([{"vendor": "cisco", "product": "ios_xe", "version": "17.9.4",
                        "component_type": "operating_system"}], kb=kb)
    assert corr2["summary"]["vulnerable"] == 0
    corr3 = correlate([{"vendor": "unknown", "product": "unknown", "version": "7.1"}], kb=kb)
    assert corr3["summary"]["unknown"] == 1


def test_golden_cve():
    cases = json.loads((Path(__file__).parent.parent / "data" / "golden_cve" / "cases.json").read_text())["cases"]
    assert len(cases) >= 200, f"only {len(cases)} golden cases"
    kb = VulnKB().load()
    bad = []
    for c in cases:
        corr = correlate([{"vendor": c["vendor"], "product": c["product"],
                           "version": c["installed"], "component_type": "t"}], kb=kb)
        got = None
        for m in corr["matches"]:
            if c["cve_id"] and m["cve_id"] == c["cve_id"]:
                got = m["status"]
                break
        if c["expected"] == "UNKNOWN":
            got = "UNKNOWN" if corr["summary"]["unknown"] else "OTHER"
        if got != c["expected"]:
            bad.append({**c, "got": got})
    assert not bad, f"{len(bad)} mismatches: {bad[:5]}"


def test_blast_radius():
    kb = VulnKB().load()
    rec = next(r for r in kb.records if r["cve_id"] == "CVE-2024-99904")
    out = assets_affected(rec, [
        {"asset_id": "FW-001", "vendor": "fortinet", "product": "fortios", "version": "7.2.2"},
        {"asset_id": "FW-003", "vendor": "fortinet", "product": "fortios", "version": "7.4.0"},
    ])
    assert [a["asset_id"] for a in out["vulnerable"]] == ["FW-001"]


def test_gateway_rule_holds_for_cve():
    for f in (Path(__file__).parent.parent / "src" / "cve").glob("*.py"):
        txt = f.read_text(encoding="utf-8")
        assert "api.featherless.ai" not in txt, f"LLM call outside gateway: {f.name}"
        assert "FEATHERLESS_API_KEY" not in txt, f"key outside gateway: {f.name}"
