"""Per-framework scoring (RTM S18; CM-082, CM-080).

There is deliberately NO single global percentage: results are reported per framework and version, with Passed / Failed /
Unknown / Not assessed counted separately. A control with no applicable resource in the upload is "not assessed", never
"passed", and unknown never counts as passed. Mappings flagged `verified: false` are reported as such, so a score can
never be mistaken for an audited benchmark result.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List

from cloud.ir import Finding
from cloud.rules.pack import Pack


def _control_status(states: List[str]) -> str:
    live = [s for s in states if s != "NOT_APPLICABLE"]
    if not live:
        return "NOT_ASSESSED"
    if any(s.startswith("FAIL") or s == "CONFLICT" for s in live):
        return "FAILED"
    if any(s.startswith("UNKNOWN") for s in live):
        return "UNKNOWN"
    return "PASSED"


def score_frameworks(findings: List[Finding], pack: Pack) -> Dict[str, Any]:
    """{framework: {version: {...counts...}}} computed from the evidence states of `findings`."""
    states: Dict[str, List[str]] = defaultdict(list)
    for f in findings:
        if not f.exception:                                  # an accepted exception is reported separately, see exceptions.py
            states[f.control_id].append(f.evidence_state)
        else:
            states[f.control_id].append("NOT_APPLICABLE" if f.exception.get("status") == "ACTIVE" else f.evidence_state)
    table: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
    for control in pack.controls:
        status = _control_status(states.get(control.id, []))
        for fw in control.frameworks:
            row = table[fw["framework"]].setdefault(str(fw.get("version", "")), {
                "controls_mapped": 0, "passed": 0, "failed": 0, "unknown": 0, "not_assessed": 0, "verified_mappings": 0,
                "failed_controls": [], "unknown_controls": []})
            row["controls_mapped"] += 1
            row[{"PASSED": "passed", "FAILED": "failed", "UNKNOWN": "unknown", "NOT_ASSESSED": "not_assessed"}[status]] += 1
            row["verified_mappings"] += bool(fw.get("verified"))
            if status == "FAILED":
                row["failed_controls"].append(control.id)
            elif status == "UNKNOWN":
                row["unknown_controls"].append(control.id)
    for versions in table.values():
        for row in versions.values():
            assessed = row["passed"] + row["failed"] + row["unknown"]
            row["evidence_completeness"] = round(assessed / row["controls_mapped"], 3) if row["controls_mapped"] else 0.0
            row["mappings_verified"] = row["verified_mappings"] == row["controls_mapped"]
            row["note"] = ("Technical evidence from the uploaded files for the controls this product maps; not an audit result"
                           + ("" if row["mappings_verified"] else " (control mappings not yet verified against the published text)") + ".")
    return {fw: dict(v) for fw, v in table.items()}
