"""Fixtures below are hand-written to the tools' documented JSON schemas (they are NOT captured from real runs); they
prove the adapters' parsing, safety and merge behaviour. Re-record real outputs when the engines are bundled."""
import json
import subprocess

import pytest

from cloud import scanners
from cloud.ir import Finding
from cloud.scanners import EngineRun, merge_findings, parse_checkov, parse_trivy, run_engine

CHECKOV = {"check_type": "terraform", "results": {
    "passed_checks": [{"check_id": "CKV_AWS_999", "check_result": {"result": "PASSED"}}],
    "failed_checks": [
        {"check_id": "CKV_AWS_24", "check_name": "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
         "file_path": "/main.tf", "file_line_range": [8, 18], "resource": "aws_security_group.public_admin", "severity": None,
         "guideline": "https://docs.example.com/ckv24"},
        {"check_id": "CKV_AWS_18", "check_name": "Ensure the S3 bucket has access logging enabled", "file_path": "/main.tf",
         "file_line_range": [20, 25], "resource": "aws_s3_bucket.b", "severity": "LOW"},
        {"check_id": "CKV_X", "check_name": "x", "file_path": "C:\\scan\\work\\mod\\a.tf", "file_line_range": [], "resource": "r",
         "severity": "weird"}]}}
TRIVY = {"SchemaVersion": 2, "Results": [{"Target": "main.tf", "Class": "config", "Type": "terraform", "Misconfigurations": [
    {"ID": "AVD-AWS-0107", "AVDID": "AVD-AWS-0107", "Title": "An ingress security group rule allows traffic from /0.", "Severity": "CRITICAL",
     "Status": "FAIL", "Resolution": "Set a more restrictive cidr range", "PrimaryURL": "https://avd.example.com/0107",
     "CauseMetadata": {"Resource": "aws_security_group.public_admin", "Provider": "AWS", "Service": "ec2", "StartLine": 12, "EndLine": 12}},
    {"ID": "AVD-AWS-0001", "Title": "ok", "Severity": "LOW", "Status": "PASS"},
    {"ID": "AVD-AWS-0002", "Title": "exc", "Severity": "LOW", "Status": "EXCEPTION"},
    {"ID": "AVD-X-1", "Title": "no cause", "Severity": "bogus"}]}, {"Target": "empty.tf"}]}


def test_checkov_failed_checks_become_tagged_findings():
    f = parse_checkov(json.dumps(CHECKOV), root="C:/scan/work", version="3.2.1")
    assert [x.control_id for x in f] == ["EXT-CHECKOV-CKV_AWS_24", "EXT-CHECKOV-CKV_AWS_18", "EXT-CHECKOV-CKV_X"]
    ssh = f[0]
    assert (ssh.evidence_state, ssh.severity, ssh.engine, ssh.rule_version) == ("FAIL_STATIC", "MEDIUM", "checkov 3.2.1", "3.2.1")
    assert ssh.source == {"file": "main.tf", "line_start": 8, "line_end": 18, "format": "external"}
    assert ssh.resource_address == "aws_security_group.public_admin" and ssh.remediation["url"].endswith("ckv24")
    assert f[1].severity == "LOW" and f[2].severity == "MEDIUM"                         # unknown severity -> labelled default
    assert f[2].source["file"] == "mod/a.tf" and f[2].source["line_start"] == 0 and f[2].remediation == {}
    assert len(parse_checkov(json.dumps([CHECKOV, "junk", {"results": None}]))) == 3     # list form, junk tolerated


def test_trivy_only_fail_status_becomes_a_finding():
    f = parse_trivy(json.dumps(TRIVY), version="0.58.0")
    assert [x.control_id for x in f] == ["EXT-TRIVY-AVD-AWS-0107", "EXT-TRIVY-AVD-X-1"]
    a = f[0]
    assert (a.severity, a.provider, a.resource_type, a.engine) == ("CRITICAL", "aws", "terraform", "trivy 0.58.0")
    assert a.source["line_start"] == 12 and a.remediation["summary"].startswith("Set a more restrictive")
    assert f[1].severity == "INFO" and f[1].source["line_start"] == 0
    assert parse_trivy("[]") == [] and parse_trivy("{}") == []
    with pytest.raises(ValueError):
        parse_trivy("{not json")


class Proc:
    def __init__(self, stdout=b"", returncode=0):
        self.stdout, self.returncode = stdout, returncode


def fake_runner(findings_json, rc=1, version=b"checkov 3.2.1\n"):
    calls = []

    def run(cmd, **kw):
        calls.append((cmd, kw))
        return Proc(version) if "--version" in cmd else Proc(findings_json, rc)
    run.calls = calls
    return run


def test_run_engine_success_uses_safe_invocation():
    runner = fake_runner(json.dumps(CHECKOV).encode())
    out = run_engine("checkov", "/scan/work", runner=runner, which=lambda n: "/usr/bin/" + n)
    assert out.status == "ok" and out.version == "checkov 3.2.1" and len(out.findings) == 3
    cmd, kw = runner.calls[-1]
    assert cmd[:3] == ["checkov", "-d", "/scan/work"] and kw["shell"] is False and kw["cwd"] == "/scan/work"
    assert kw["timeout"] == scanners.TIMEOUT_SECONDS and "AWS_SECRET_ACCESS_KEY" not in kw["env"] and kw["env"]["HOME"] == "/tmp"


def test_run_engine_never_reports_missing_or_broken_tools_as_clean():
    assert run_engine("checkov", "/w", which=lambda n: None).status == "unavailable"
    assert run_engine("nope", "/w").status == "failed"
    which = lambda n: "/x"
    assert run_engine("checkov", "/w", runner=fake_runner(b"", 0), which=which).error == "exit code 0"
    assert run_engine("checkov", "/w", runner=fake_runner(b"{}", 2), which=which).error == "exit code 2"
    assert run_engine("checkov", "/w", runner=fake_runner(b"{not json", 1), which=which).error.startswith("unreadable output")
    big = b"x" * (scanners.MAX_OUTPUT_BYTES + 1)
    assert run_engine("checkov", "/w", runner=fake_runner(big, 1), which=which).error == "output too large"

    def timeout(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 1)

    def oserror(cmd, **kw):
        raise PermissionError("denied")

    assert run_engine("trivy", "/w", runner=timeout, which=which).error == "timed out"
    assert run_engine("trivy", "/w", runner=oserror, which=which).error == "could not start: PermissionError"
    assert run_engine("trivy", "/w", runner=fake_runner(json.dumps(TRIVY).encode(), 0, b""), which=which).version == ""


def orbit_finding(control="CLOUD-NET-001", address="aws_security_group.public_admin", file="main.tf", state="FAIL_STATIC"):
    return Finding(control, "t", "HIGH", state, address, "aws_security_group", "aws", [], {"file": file, "line_start": 8})


def test_merge_deduplicates_equivalent_checks_and_keeps_the_rest():
    own = [orbit_finding(), orbit_finding("CLOUD-NET-003", state="PASS_STATIC")]
    ext = parse_checkov(json.dumps(CHECKOV), version="3.2.1") + parse_trivy(json.dumps(TRIVY), version="0.58.0")
    merged = merge_findings(own, ext)
    ids = [f.control_id for f in merged]
    assert "EXT-CHECKOV-CKV_AWS_24" not in ids                                       # duplicate of CLOUD-NET-001: merged
    assert "also reported by checkov 3.2.1 CKV_AWS_24" in own[0].notes
    assert "EXT-CHECKOV-CKV_AWS_18" in ids and "EXT-TRIVY-AVD-AWS-0107" in ids       # no Orbit equivalent: kept, tagged by engine
    again = merge_findings(own, ext)
    assert own[0].notes.count("also reported by checkov 3.2.1 CKV_AWS_24") == 1       # idempotent notes
    assert len([f for f in again if f.control_id == "EXT-CHECKOV-CKV_AWS_18"]) == 1
    twice = merge_findings([], ext + ext)
    assert len(twice) == len(set((f.control_id, f.resource_address, f.source["line_start"]) for f in ext))


def test_equivalent_is_not_merged_when_orbit_did_not_fail_the_resource():
    own = [orbit_finding(state="UNKNOWN_STATIC")]
    ext = parse_checkov(json.dumps(CHECKOV), version="3.2.1")
    assert any(f.control_id == "EXT-CHECKOV-CKV_AWS_24" for f in merge_findings(own, ext))
    assert EngineRun("x", "ok").findings == []
    assert merge_findings([], [Finding("EXT-X", "t", "LOW", "FAIL_STATIC", "a", "t", "p", [], {})])[0].control_id == "EXT-X"
