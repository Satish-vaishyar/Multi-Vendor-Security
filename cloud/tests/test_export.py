import csv
import io
import json

from cloud import export

REPORT = {"rule_pack_version": "1", "findings": [
    {"control_id": "CLOUD-NET-001", "title": "SSH open", "severity": "HIGH", "evidence_state": "FAIL_STATIC", "provider": "aws",
     "resource_type": "aws_security_group", "resource_address": "=HYPERLINK(\"x\")", "source": {"file": "m.tf", "line_start": 3},
     "remediation": {"summary": "Restrict"}, "exception": {"id": "EX1"}},
    {"control_id": "CLOUD-NET-002", "title": "unsure", "severity": "LOW", "evidence_state": "UNKNOWN_STATIC", "source": {}},
    {"control_id": "CLOUD-IAM-001", "title": "t", "severity": "ZZ", "evidence_state": "FAIL_STATIC", "source": {"line_start": 0},
     "exception": "EX2"}]}


def test_csv_neutralises_formulas_and_lists_every_finding():
    rows = list(csv.reader(io.StringIO(export.to_csv(REPORT))))
    assert rows[0][0] == "control_id" and len(rows) == 4
    assert rows[1][6].startswith("'=") and rows[1][10] == "EX1" and rows[3][10] == "EX2"
    assert export.csv_cell(None) == "" and export.csv_cell("a") == "a" and export.csv_cell("@x").startswith("'")


def test_sarif_has_only_failures_and_valid_lines():
    doc = json.loads(export.to_sarif(REPORT))
    res = doc["runs"][0]["results"]
    assert [r["ruleId"] for r in res] == ["CLOUD-NET-001", "CLOUD-IAM-001"]
    assert res[0]["level"] == "error" and res[1]["level"] == "warning"
    assert res[1]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    assert len(doc["runs"][0]["tool"]["driver"]["rules"]) == 2


def test_json_export_redacts_secrets():
    key = "AK" + "IAQWERTYUIOPASDFGH"
    out = export.to_json({"findings": [{"title": f"key {key}"}]})
    assert key not in out and json.loads(out)


def test_json_and_sarif_redact_keys_nested_values_and_locations():
    key = "AK" + "IAQWERTYUIOPASDFGH"
    out = export.to_json({key: [{"a": key}, (key,), 3, None, object.__name__ and 1.5, {"k": True}]})
    assert key not in out
    rep = {"rule_pack_version": key, "findings": [{"control_id": key, "title": "t", "severity": "HIGH", "evidence_state": "FAIL_STATIC",
                                                   "source": {"file": key + ".tf", "line_start": 2}}]}
    assert key not in export.to_sarif(rep) and key not in export.to_json({"x": object()})


def test_json_redacts_values_by_key_context():
    out = json.loads(export.to_json({"password": "hunter2", "aws_secret_access_key": "abc", "private_key_id": "k1", "name": "web",
                                     "n": {"api_key": "zzz", "empty": "", "title": "ok"}, "tags": ["a"]}))
    assert out["password"] == out["aws_secret_access_key"] == out["private_key_id"] == out["n"]["api_key"] == "[REDACTED]"
    assert out["name"] == "web" and out["n"]["empty"] == "" and out["tags"] == ["a"]
    assert export._redact_entry("note", 'password = "hunter2hunter2"') in ("[REDACTED]", 'password = "hunter2hunter2"')


def test_whole_subtree_under_a_credential_key_is_masked():
    out = json.loads(export.to_json({"secret": {"a": [1, "x", {"b": 2.5, "c": None}], "d": ""}, "tokens": ["t1", 7], "token": 123456,
                                     "passwords": [], "ok": {"n": 1}}))
    assert out["secret"] == {"a": ["[REDACTED]", "[REDACTED]", {"b": "[REDACTED]", "c": None}], "d": ""}
    assert out["tokens"] == ["[REDACTED]", "[REDACTED]"] and out["token"] == "[REDACTED]" and out["passwords"] == [] and out["ok"] == {"n": 1}


def test_pdf_is_wellformed_redacted_and_paginated():
    import re

    from cloud.export import PDF_LINES_PER_PAGE, PDF_MAX_FINDINGS, to_pdf
    secret = "AKIA" + "ABCDEFGHIJKLMNOP"
    f = {"severity": "HIGH", "evidence_state": "FAIL_STATIC", "control_id": "C-1", "title": f"bad (paren) \ {secret} ☃",
         "resource_address": "a.b", "source": {"file": "m.tf", "line_start": 3}}
    rep = {"statement": "s", "coverage": {"providers": ["aws"], "formats": {"x": 1}, "not_assessed": ["live"], "rule_pack_customisations": ["c"]},
           "summary": {"states": {"FAIL_STATIC": 1}}, "input": {"filename": "f", "sha256": "h"}, "findings": [f] * (PDF_MAX_FINDINGS + 1) + ["junk"]}
    pdf = to_pdf(rep)
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF") and secret.encode() not in pdf
    assert rb"\(paren\)" in pdf and rb"more finding\(s\)" in pdf
    start = int(re.search(rb"startxref\n(\d+)", pdf).group(1))
    assert pdf[start:start + 4] == b"xref"
    offs = re.findall(rb"(\d{10}) 00000 n", pdf)
    for n, off in enumerate(offs, 1):
        assert pdf[int(off):].startswith(b"%d 0 obj" % n)
    assert pdf.count(b"/Type /Page ") > 2 and PDF_LINES_PER_PAGE > 0
    straddle = {"statement": "x" * 90 + " " + secret + " tail"}      # the secret crosses the wrap column
    assert b"ABCDEFGH" not in to_pdf(straddle) and b"IJKLMNOP" not in to_pdf(straddle)
    assert to_pdf({}).startswith(b"%PDF")          # an empty report still yields one page
