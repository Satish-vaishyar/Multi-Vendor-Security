"""Measure how well the product understands a set of REAL configurations.

This is the harness that turns a pilot into evidence. Point it at a directory of (anonymised) configs; for each file
it reports vendor-detection correctness, the share of configuration lines the parsers understood, and - the number a
buyer cares about - false "compliant": a control the operator said must FAIL (a seeded known-bad setting) that the
product reported as PASS or could not decide.

Optional sidecar ``<file>.expect.json``:
    {"vendor": "cisco", "must_fail": ["CIS-1.1.1", ...], "must_pass": ["..."]}
Without a sidecar the file is still scored for parse coverage and detection confidence.

Pilot bar (docs/PRODUCT_BRIEF.md): >= 95 % of lines understood and ZERO false compliant on the seeded set.
Read-only: nothing is written to the database.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List

from app.parsers import canonical as canon
from app.parsers import vendor_detector
from app.services.integration import okf_layer

EXTS = {".cfg", ".conf", ".txt", ".config", ".set", ".json"}
PILOT_UNDERSTOOD_PCT = 95.0
_COMMENT = ("!", "#", "//", ";", "/*", "*")


def _meaningful_lines(text: str) -> int:
    return sum(1 for ln in text.splitlines() if ln.strip() and not ln.strip().startswith(_COMMENT))


def analyse(text: str, frameworks: List[str] | None = None):
    """detect -> parse -> evaluate every control. Returns (detection, parsed, {control_id: status}). Read-only."""
    det = vendor_detector.detect_vendor(text, "")
    parsed = canon.parse_to_canonical(text, det["vendor_id"], str(det.get("platform") or ""))
    okf = okf_layer()
    controls = okf["ckb"].for_frameworks(frameworks or ["CIS", "NIST", "STIG", "ISO27001"])
    eng = okf["ComplianceEngine"](controls, {})
    findings = eng.evaluate(parsed["nested_ir"], asset_id="EVAL", vendor=det["vendor_id"],
                            platform=str(det.get("platform") or ""), not_applicable=parsed.get("not_applicable"),
                            provenance=parsed.get("provenance"))
    return det, parsed, {f.control_id: f.status for f in findings}


def control_statuses(text: str, frameworks: List[str] | None = None):
    det, _parsed, status = analyse(text, frameworks)
    return det, status


def evaluate_file(path: Path, frameworks: List[str] | None = None) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    exp: Dict[str, Any] = {}
    side = path.with_name(path.name + ".expect.json")
    if side.exists():
        exp = json.loads(side.read_text(encoding="utf-8"))
    det, parsed, status = analyse(text, frameworks)
    total = _meaningful_lines(text)
    unknown = len(parsed.get("unknown_lines") or [])
    understood = round(100.0 * max(total - unknown, 0) / total, 1) if total else 0.0
    must_fail = list(exp.get("must_fail") or [])
    must_pass = list(exp.get("must_pass") or [])
    false_compliant = [c for c in must_fail if status.get(c) != "FAIL"]       # PASS, UNKNOWN or missing: all unacceptable
    false_alarm = [c for c in must_pass if status.get(c) == "FAIL"]
    row: Dict[str, Any] = {
        "file": path.name, "vendor_detected": det["vendor_id"], "platform": det.get("platform"),
        "vendor_expected": exp.get("vendor"), "vendor_ok": (exp["vendor"].lower() == det["vendor_id"].lower()) if exp.get("vendor") else None,
        "lines": total, "unknown_lines": unknown, "understood_pct": understood,
        "controls": {s: sum(1 for v in status.values() if v == s) for s in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE")},
        "must_fail": must_fail, "false_compliant": false_compliant, "must_pass": must_pass, "false_alarm": false_alarm,
    }
    return row


def evaluate_dir(directory: Path, frameworks: List[str] | None = None) -> Dict[str, Any]:
    files = sorted(p for p in directory.rglob("*") if p.is_file() and p.suffix.lower() in EXTS and not p.name.endswith(".expect.json"))
    rows, errors = [], []
    for p in files:
        try:
            rows.append(evaluate_file(p, frameworks))
        except Exception as e:                                    # one broken file must not hide the other results
            errors.append({"file": p.name, "error": f"{type(e).__name__}: {e}"[:300]})
    labelled = [r for r in rows if r["vendor_ok"] is not None]
    lines = sum(r["lines"] for r in rows)
    unknown = sum(r["unknown_lines"] for r in rows)
    summary = {
        "files": len(rows), "errors": len(errors),
        "vendor_accuracy_pct": round(100.0 * sum(1 for r in labelled if r["vendor_ok"]) / len(labelled), 1) if labelled else None,
        "understood_pct_overall": round(100.0 * (lines - unknown) / lines, 1) if lines else 0.0,
        "understood_pct_worst_file": min((r["understood_pct"] for r in rows), default=0.0),
        "seeded_checks": sum(len(r["must_fail"]) for r in rows),
        "false_compliant_total": sum(len(r["false_compliant"]) for r in rows),
        "false_alarm_total": sum(len(r["false_alarm"]) for r in rows),
    }
    summary["meets_pilot_bar"] = bool(rows) and not errors and summary["understood_pct_overall"] >= PILOT_UNDERSTOOD_PCT \
        and summary["false_compliant_total"] == 0 and summary["seeded_checks"] > 0
    return {"summary": summary, "files": rows, "errors": errors}


def to_markdown(report: Dict[str, Any]) -> str:
    s = report["summary"]
    out = ["# Corpus evaluation", "",
           f"* files: **{s['files']}** (errors: {s['errors']})",
           f"* vendor detection accuracy: **{s['vendor_accuracy_pct']}%**" if s["vendor_accuracy_pct"] is not None else "* vendor detection: no labelled files",
           f"* lines understood overall: **{s['understood_pct_overall']}%** (worst file {s['understood_pct_worst_file']}%)",
           f"* seeded known-bad checks: {s['seeded_checks']}, **false compliant: {s['false_compliant_total']}**, false alarms: {s['false_alarm_total']}",
           f"* meets the pilot bar (>= {PILOT_UNDERSTOOD_PCT:.0f}% understood, 0 false compliant, seeded checks present): "
           f"**{'YES' if s['meets_pilot_bar'] else 'NO'}**", "",
           "| file | vendor | understood | PASS | FAIL | UNKNOWN | false compliant |", "|---|---|---|---|---|---|---|"]
    for r in report["files"]:
        c = r["controls"]
        out.append(f"| {r['file']} | {r['vendor_detected']}{'' if r['vendor_ok'] in (None, True) else ' (EXPECTED ' + str(r['vendor_expected']) + ')'} "
                   f"| {r['understood_pct']}% | {c['PASS']} | {c['FAIL']} | {c['UNKNOWN']} | {', '.join(r['false_compliant']) or '-'} |")
    for e in report["errors"]:
        out.append(f"| {e['file']} | ERROR | - | - | - | - | {e['error']} |")
    return "\n".join(out) + "\n"
