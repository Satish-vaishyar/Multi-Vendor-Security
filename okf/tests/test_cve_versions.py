"""Real-world vendor version formats vs. advisory ranges (P1-7 regression suite)."""
import pytest
from src.cve.version_normalizer import normalize
from src.cve.version_range import match_record


def rng(start=None, end=None, end_inclusive=False, fixed=None):
    return [{"start": start, "start_inclusive": True, "end": end, "end_inclusive": end_inclusive, "fixed": fixed}]


CASES = [
    # (installed, ranges, affected?, why)
    ("10.2.3-h4", rng("10.2.0", "10.2.3"), False, "PAN-OS hotfix of the fixed base is not affected"),
    ("10.2.2-h1", rng("10.2.0", "10.2.3"), True, "PAN-OS hotfix below fix"),
    ("17.9.4a", rng("17.9.0", "17.9.4"), False, "IOS-XE rebuild after the fixed base"),
    ("17.9.3a", rng("17.9.0", "17.9.4"), True, "rebuild below the fix"),
    ("17.9.4a", rng("17.0", "17.9.4", True, fixed="17.9.5"), True, "rebuild of last affected build is below the fix"),
    ("4.28.4M", rng("4.28.0", "4.28.4"), False, "EOS train letter after fixed base"),
    ("4.28.3M", rng("4.28.0", "4.28.4"), True, "EOS below fix"),
    ("10.3(4a)", rng("10.3(1)", "10.3(4)"), False, "NX-OS rebuild after fixed base"),
    ("10.3(3)", rng("10.3(1)", "10.3(4)"), True, "NX-OS below fix"),
    ("20.4R3", rng("20.4R1", "20.4R3-S1"), True, "Junos R3 is before R3-S1"),
    ("20.4R3-S1", rng("20.4R1", "20.4R3-S1"), False, "Junos at the fixed service release"),
    ("20.4R3-S2", rng("20.4R1", "20.4R3-S4"), True, "Junos S2 < S4"),
    ("20.4R3-S2", [{"start": "20.4:r3-s2", "start_inclusive": True, "end": "20.4:r3-s2", "end_inclusive": True}], True,
     "exact CPE version:update form"),
    ("7.2.10", rng("7.2.2", "7.2.5"), False, "FortiOS numeric not lexical"),
    ("7.2.0", rng("7.2", "7.2.5"), True, "7.2 == 7.2.0"),
]


@pytest.mark.parametrize("installed,ranges,expected,why", CASES, ids=[c[3] for c in CASES])
def test_real_world_versions(installed, ranges, expected, why):
    assert match_record(installed, ranges)["affected"] is expected, why


def test_post_release_ordering():
    assert normalize("17.9.4") < normalize("17.9.4a") < normalize("17.9.4b") < normalize("17.9.5")
    assert normalize("20.4R3-S2") < normalize("20.4R3-S2.1") < normalize("20.4R3-S4")
    assert normalize("15.2(4)M9") < normalize("15.2(4)M10")
    assert normalize("10.2.3-rc1") < normalize("10.2.3") < normalize("10.2.3-h1")
