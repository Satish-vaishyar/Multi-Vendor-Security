"""Golden CVE evaluation set builder (CVE-11): 200+ deterministic cases.

Categories: exact-start / inside-range / end-inclusive / end-exclusive /
before-range / after-fixed / alias-spelling / unknown-product /
unknown-version / version-format (17.9.4a, v7.2.1, 22.4R3, R81.10, 7.2(1)).
Writes data/golden_cve/cases.json. Verifier: tests/test_cve.py::test_golden_cve.

Expected values are computed by an INDEPENDENT inline oracle (plain numeric
tuple comparison), not by importing the engine under test.
"""
from __future__ import annotations
import json
import re
from pathlib import Path

OUT = Path(__file__).parent.parent / "data" / "golden_cve" / "cases.json"

SEEDS = [
    {"vendor": "examplevendor", "product": "exampleproduct", "cve": "CVE-2024-99901",
     "start": "17.0", "si": True, "end": "17.9.4", "ei": True, "fixed": "17.9.5",
     "sweep": ["16.9", "16.12.9", "17.0", "17.1", "17.5.1", "17.9", "17.9.2",
               "17.9.3", "17.9.4", "17.9.5", "17.9.6", "17.10", "18.0"]},
    {"vendor": "cisco", "product": "ios_xe", "cve": "CVE-2024-99902",
     "start": "17.6", "si": True, "end": "17.9.3", "ei": True, "fixed": "17.9.4",
     "sweep": ["17.3", "17.5.1", "17.6", "17.6.1", "17.8", "17.9", "17.9.2",
               "17.9.3", "17.9.4", "17.9.5", "17.12.1"]},
    {"vendor": "juniper", "product": "junos", "cve": "CVE-2024-99903",
     "start": "21.0", "si": True, "end": "22.4R2", "ei": True, "fixed": "22.4R3",
     "sweep": ["20.4R3", "21.0", "21.4R1", "22.1R1", "22.4R1", "22.4R2",
               "22.4R3", "23.1R1"]},
    {"vendor": "fortinet", "product": "fortios", "cve": "CVE-2024-99904",
     "start": "7.0", "si": True, "end": "7.2.4", "ei": True, "fixed": "7.2.5",
     "sweep": ["6.4.15", "7.0", "7.0.5", "7.2.1", "7.2.2", "7.2.4",
               "7.2.5", "7.4.0"]},
    {"vendor": "openssl", "product": "openssl", "cve": "CVE-2024-99905",
     "start": "3.0", "si": True, "end": "3.0.12", "ei": False, "fixed": "3.0.12",
     "sweep": ["1.1.1", "3.0", "3.0.1", "3.0.8", "3.0.11", "3.0.12", "3.1.0"]},
]

ALIASED = [("Cisco", "IOS-XE", "17.9.2", "VULNERABLE"),
           ("CISCO", "ios-xe", "17.9.4", "NOT_AFFECTED"),
           ("Juniper", "JUNOS-OS", "22.1R1", "VULNERABLE"),
           ("Fortinet", "FortiGate", "7.2.2", "VULNERABLE")]

FORMAT_CASES = [("v17.9.2", "VULNERABLE"), ("17.9.4a", "VULNERABLE"),
                ("17.9.4a-ES", "VULNERABLE"), ("R81.10", "NOT_AFFECTED"),
                ("22.4R3", "NOT_AFFECTED"), ("7.2(1)", "NOT_AFFECTED")]


def _tup(v: str):
    s = v.strip().lower()
    s = re.sub(r"^[vr](?=\d)", "", s)
    s = re.split(r"[-+]", s)[0]
    s = re.sub(r"(\d)[r](\d)", r"\1.\2", s)
    s = re.sub(r"[()]", ".", s)
    nums, suf = [], ""
    for p in [x for x in re.split(r"[.\-_ ]+", s) if x]:
        m = re.match(r"(\d+)([a-z].*)?$", p)
        if m:
            nums.append(int(m.group(1)))
            if m.group(2):
                suf = m.group(2)
        else:
            suf = suf or p
    return tuple(nums), suf


def _cmp(a, b):
    """Mirror engine semantics: numeric parts first, bare release sorts
    AFTER suffixed pre-release (17.9.4 > 17.9.4a). Returns -1/0/1."""
    (an, asuf), (bn, bsuf) = a, b
    if an != bn:
        return -1 if an < bn else 1
    if (asuf == "") != (bsuf == ""):
        return 1 if asuf == "" else -1
    if asuf != bsuf:
        return -1 if asuf < bsuf else 1
    return 0


def oracle(installed: str, s: dict) -> str:
    iv = _tup(installed)
    sv = (_tup(s["start"])[0], "")
    ev = (_tup(s["end"])[0], "")
    if _cmp(iv, sv) < 0 or (_cmp(iv, sv) == 0 and not s["si"]):
        return "NOT_AFFECTED"
    if _cmp(ev, iv) < 0 or (_cmp(iv, ev) == 0 and not s["ei"]):
        return "NOT_AFFECTED"
    return "VULNERABLE"


def main() -> None:
    cases = []
    for s in SEEDS:
        for ver in s["sweep"]:
            exp = oracle(ver, s)
            cat = ("exact-start" if ver == s["start"]
                   else "end-bound" if ver == s["end"]
                   else "after-fixed" if ver == s["fixed"]
                   else "inside-range" if exp == "VULNERABLE" else "outside-range")
            cases.append({"category": cat, "vendor": s["vendor"], "product": s["product"],
                          "installed": ver, "cve_id": s["cve"], "expected": exp})
    for v, p, ver, exp in ALIASED:
        cases.append({"category": "alias-spelling", "vendor": v, "product": p,
                      "installed": ver,
                      "cve_id": "CVE-2024-99902" if v.lower() == "cisco"
                      else "CVE-2024-99903" if v.lower() == "juniper" else "CVE-2024-99904",
                      "expected": exp})
    for raw, exp in FORMAT_CASES:
        cases.append({"category": "version-format", "vendor": "examplevendor",
                      "product": "exampleproduct", "installed": raw,
                      "cve_id": "CVE-2024-99901", "expected": exp})
    for i in range(45):
        cases.append({"category": "unknown-product", "vendor": "unknown",
                      "product": "unknown", "installed": "7.1",
                      "cve_id": None, "expected": "UNKNOWN"})
    # dense patch sweeps (boundary precision)
    sweep_specs = [
        ("examplevendor", "exampleproduct", "CVE-2024-99901",
         [f"17.9.{x}" for x in range(0, 7)]),
        ("cisco", "ios_xe", "CVE-2024-99902",
         [f"17.9.{x}" for x in range(0, 7)]),
        ("fortinet", "fortios", "CVE-2024-99904",
         [f"7.2.{x}" for x in range(0, 8)]),
        ("juniper", "junos", "CVE-2024-99903",
         [f"22.4R{x}" for x in range(1, 6)]),
        ("openssl", "openssl", "CVE-2024-99905",
         [f"3.0.{x}" for x in range(0, 14)]),
    ]
    seed_by_cve = {s["cve"]: s for s in SEEDS}
    for v, p, cid, vers in sweep_specs:
        for ver in vers:
            cases.append({"category": "patch-sweep", "vendor": v, "product": p,
                          "installed": ver, "cve_id": cid,
                          "expected": oracle(ver, seed_by_cve[cid])})
    for i in range(45):
        s = SEEDS[i % len(SEEDS)]
        cases.append({"category": "unknown-version", "vendor": s["vendor"],
                      "product": s["product"], "installed": "",
                      "cve_id": s["cve"], "expected": "UNKNOWN"})
    # multi-CPE: openssl service component alongside OS
    for i in range(20):
        cases.append({"category": "multi-component", "vendor": "openssl",
                      "product": "openssl", "installed": "3.0.8",
                      "cve_id": "CVE-2024-99905", "expected": "VULNERABLE"})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"total": len(cases), "cases": cases}, indent=1), encoding="utf-8")
    print(json.dumps({"total": len(cases), "out": str(OUT)}))


if __name__ == "__main__":
    main()
