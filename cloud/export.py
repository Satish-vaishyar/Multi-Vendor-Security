"""Report export (RTM S20; CM-122): JSON, CSV and SARIF 2.1.0 built from a completed scan report.

Everything exported is re-redacted (the report may have been stored and edited), and CSV cells that a spreadsheet could
interpret as a formula are neutralised so an uploaded resource name cannot execute in the reviewer's Excel/Sheets.
PDF is not produced here: it needs a renderer the sandboxed service does not ship.
"""
from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, List

from cloud import secret_scan

CSV_COLUMNS = ("control_id", "title", "severity", "evidence_state", "provider", "resource_type", "resource_address",
               "file", "line", "engine", "exception", "remediation")
_FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}


def csv_cell(value: Any) -> str:
    """Text safe to open in a spreadsheet: redacted, and prefixed with ' when it could be read as a formula."""
    text = secret_scan.redact("" if value is None else str(value))
    return "'" + text if text.startswith(_FORMULA_LEAD) else text


def to_json(report: Dict[str, Any]) -> str:
    return json.dumps(json.loads(secret_scan.redact(json.dumps(report, default=str))), indent=2, sort_keys=True)


def to_csv(report: Dict[str, Any]) -> str:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for f in report.get("findings", []):
        src = f.get("source") or {}
        w.writerow([csv_cell(v) for v in (
            f.get("control_id"), f.get("title"), f.get("severity"), f.get("evidence_state"), f.get("provider"),
            f.get("resource_type"), f.get("resource_address"), src.get("file"), src.get("line_start"), f.get("engine"),
            (f.get("exception") or {}).get("id") if isinstance(f.get("exception"), dict) else f.get("exception"),
            (f.get("remediation") or {}).get("summary"))])
    return out.getvalue()


def to_sarif(report: Dict[str, Any]) -> str:
    """Only failed findings become SARIF results; UNKNOWN is a coverage gap, not a defect, and stays in the JSON."""
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for f in report.get("findings", []):
        if f.get("evidence_state") not in ("FAIL_STATIC", "FAIL_LIVE"):
            continue
        rules.setdefault(f["control_id"], {"id": f["control_id"], "shortDescription": {"text": secret_scan.redact(str(f.get("title", "")))}})
        src = f.get("source") or {}
        loc = {"physicalLocation": {"artifactLocation": {"uri": str(src.get("file", ""))},
                                    "region": {"startLine": max(int(src.get("line_start") or 1), 1)}}}
        results.append({"ruleId": f["control_id"], "level": _SARIF_LEVEL.get(f.get("severity"), "warning"),
                        "message": {"text": secret_scan.redact(f"{f.get('title', '')} ({f.get('resource_address', '')})")},
                        "locations": [loc]})
    doc = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
           "runs": [{"tool": {"driver": {"name": "orbit-cloud-static", "version": str(report.get("rule_pack_version", "")),
                                         "rules": list(rules.values())}}, "results": results}]}
    return json.dumps(doc, indent=2)
