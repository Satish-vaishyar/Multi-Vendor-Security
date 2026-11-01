"""Report export (RTM S20; CM-122): JSON, CSV and SARIF 2.1.0 built from a completed scan report.

Everything exported is re-redacted (the report may have been stored and edited), and CSV cells that a spreadsheet could
interpret as a formula are neutralised so an uploaded resource name cannot execute in the reviewer's Excel/Sheets.
PDF is a small dependency-free text report written by `to_pdf` (no renderer, nothing fetched or executed).
"""
from __future__ import annotations

import csv
import io
import json
import re
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


_SENSITIVE_KEY = re.compile(r"pass(word|wd)?|secret|token|credential|private[_-]?key|access[_-]?key|api[_-]?key|auth", re.I)


def _redact(value: Any) -> Any:
    """Redact every string (keys and values) of the structure itself; never run the regex over serialised JSON, where
    escaping could split a credential from the pattern that matches it."""
    if isinstance(value, str):
        return secret_scan.redact(value)
    if isinstance(value, dict):
        return {secret_scan.redact(str(k)): _redact_entry(str(k), v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value]
    return value if value is None or isinstance(value, (bool, int, float)) else secret_scan.redact(str(value))


def _mask(value: Any) -> Any:
    """Every leaf of a subtree under a credential-looking key, whatever its type (numbers and booleans included)."""
    if isinstance(value, dict):
        return {secret_scan.redact(str(k)): _mask(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_mask(v) for v in value]
    return "[REDACTED]" if value not in (None, "") else value


def _redact_entry(key: str, value: Any) -> Any:
    """A value under a credential-looking key is dropped outright (the key is the context the value-only scan lacks); other
    strings are also scanned as `key = "value"` so assignment-shaped secrets are caught."""
    if _SENSITIVE_KEY.search(key) and value not in (None, "", [], {}):
        return _mask(value)
    if isinstance(value, str):
        scanned = secret_scan.redact(f'{key} = "{value}"')
        return secret_scan.redact(value) if scanned == f'{key} = "{value}"' else "[REDACTED]"
    return _redact(value)


def to_json(report: Dict[str, Any]) -> str:
    return json.dumps(_redact(report), indent=2, sort_keys=True)


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
        rule_id = secret_scan.redact(str(f["control_id"]))
        rules.setdefault(rule_id, {"id": rule_id, "shortDescription": {"text": secret_scan.redact(str(f.get("title", "")))}})
        src = f.get("source") or {}
        loc = {"physicalLocation": {"artifactLocation": {"uri": secret_scan.redact(str(src.get("file", "")))},
                                    "region": {"startLine": max(int(src.get("line_start") or 1), 1)}}}
        results.append({"ruleId": rule_id, "level": _SARIF_LEVEL.get(f.get("severity"), "warning"),
                        "message": {"text": secret_scan.redact(f"{f.get('title', '')} ({f.get('resource_address', '')})")},
                        "locations": [loc]})
    doc = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
           "runs": [{"tool": {"driver": {"name": "orbit-cloud-static", "version": secret_scan.redact(str(report.get("rule_pack_version", ""))),
                                         "rules": list(rules.values())}}, "results": results}]}
    return json.dumps(doc, indent=2)


# ------------------------------------------------------------------ PDF (RTM S20): a dependency-free, text-only report
PDF_LINE_WIDTH = 98
PDF_LINES_PER_PAGE = 60
PDF_MAX_FINDINGS = 2000


def _pdf_text(value: Any) -> str:
    """Redacted, control characters removed, latin-1 only (the built-in Helvetica font), then PDF string escaping."""
    text = secret_scan.redact("" if value is None else str(value))
    text = "".join(c if c.isprintable() else " " for c in text).encode("latin-1", "replace").decode("latin-1")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap(line: str) -> List[str]:
    return [line[i:i + PDF_LINE_WIDTH] for i in range(0, max(len(line), 1), PDF_LINE_WIDTH)]


def _report_lines(report: Dict[str, Any]) -> List[str]:
    cov = report.get("coverage") or {}
    summary = report.get("summary") or {}
    inp = report.get("input") or {}
    lines = ["Cloud security assessment report", "",
             f"Scan input: {inp.get('filename', '')}  sha256 {inp.get('sha256', '')}",
             f"Rule pack: {report.get('rule_pack_version', '')}   Mode: {report.get('mode', 'static')}   Status: {report.get('status', '')}", "",
             "Statement", str(report.get("statement", "")), "", "Coverage",
             f"Providers: {', '.join(map(str, cov.get('providers') or [])) or 'none detected'}",
             f"Formats: {json.dumps(cov.get('formats') or {}, sort_keys=True)}",
             f"Not assessed: {'; '.join(map(str, cov.get('not_assessed') or []))}"]
    for note in cov.get("rule_pack_customisations") or []:
        lines.append(f"Customisation: {note}")
    lines += ["", "Summary", f"Results by state: {json.dumps(summary.get('states') or {}, sort_keys=True)}",
              f"Failed by severity: {json.dumps(summary.get('failed_by_severity') or {}, sort_keys=True)}", "",
              "Findings (UNKNOWN means undecidable from the files; it is never counted as a pass)"]
    findings = [f for f in report.get("findings") or [] if isinstance(f, dict)]
    for f in findings[:PDF_MAX_FINDINGS]:
        src = f.get("source") or {}
        lines.append(f"[{f.get('severity', '')}] {f.get('evidence_state', '')}  {f.get('control_id', f.get('rule_id', ''))}  {f.get('title', '')}")
        lines.append(f"    {f.get('resource_address', src.get('resource_address', ''))}  {src.get('file', '')}:{src.get('line_start', '')}")
    if len(findings) > PDF_MAX_FINDINGS:
        lines.append(f"... {len(findings) - PDF_MAX_FINDINGS} more finding(s) are in the JSON export")
    return lines


def to_pdf(report: Dict[str, Any]) -> bytes:
    # redact the WHOLE logical line before wrapping: wrapping first could split a credential across two lines
    wrapped = [w for line in _report_lines(report) for w in _wrap(secret_scan.redact(line))]
    pages = [wrapped[i:i + PDF_LINES_PER_PAGE] for i in range(0, len(wrapped), PDF_LINES_PER_PAGE)] or [[]]
    objs: List[bytes] = [b"<< /Type /Catalog /Pages 2 0 R >>", b"", b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"]
    kids = []
    for lines in pages:
        stream = "BT /F1 8 Tf 10 TL 36 806 Td " + " ".join(f"({_pdf_text(l)}) '" for l in lines) + " ET"
        body = stream.encode("latin-1", "replace")
        objs.append(b"<< /Length %d >>\nstream\n" % len(body) + body + b"\nendstream")
        objs.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>" % len(objs))
        kids.append(len(objs))
    objs[1] = b"<< /Type /Pages /Kids [" + b" ".join(b"%d 0 R" % k for k in kids) + b"] /Count %d >>" % len(kids)
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for n, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % n + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)
