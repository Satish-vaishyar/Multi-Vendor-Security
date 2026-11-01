"""Fixtures below are hand-written to the tools' documented JSON schemas (they are NOT captured from real runs); they
prove the adapters' parsing, safety and merge behaviour. Re-record real outputs when the engines are bundled."""
import io
import json
import os
import subprocess
import time

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


class FakeProc:
    def __init__(self, data, rc, delay=0.0):
        self.rc, self.killed, self.returncode = rc, False, rc
        self.stdout = _Stream(data, delay)

    def kill(self):
        self.killed = True

    def wait(self):
        return self.rc


class _Stream:
    def __init__(self, data, delay):
        self.buf, self.delay = io.BytesIO(data), delay

    def read(self, n):
        if self.delay:
            time.sleep(self.delay)
        return self.buf.read(n)


def fake_popen(findings_json, rc=1, version=b"checkov 3.2.1\n", record=None, snoop=None, delay=0.0):
    record = record if record is not None else []

    def popen(cmd, **kw):
        record.append((cmd, kw))
        if snoop:
            snoop(cmd, kw)
        is_version = "--version" in cmd
        return FakeProc(version if is_version else findings_json, 0 if is_version else rc, 0.0 if is_version else delay)
    return popen


def tree(tmp_path):
    (tmp_path / "sub").mkdir()
    for name, body in {"main.tf": "x", "sub/a.yaml": "k: v", ".checkov.yaml": "soft-fail: true", "trivy.yaml": "ignore: all",
                       ".trivyignore": "AVD-1", "evil.py": "import os", "notes.txt": "n", "sub/checkov.yml": "x"}.items():
        (tmp_path / name).write_text(body, encoding="utf-8")
    return str(tmp_path)


def test_scan_copy_excludes_tool_configuration_ignore_files_and_code(tmp_path):
    (tmp_path / "src").mkdir()
    tree(tmp_path / "src")
    dst = str(tmp_path / "dst")
    n = scanners.prepare_scan_dir(str(tmp_path / "src"), dst)
    names = sorted(str(p.relative_to(dst)).replace(chr(92), "/") for p in __import__("pathlib").Path(dst).rglob("*") if p.is_file())
    assert names == ["main.tf", "sub/a.yaml"] and n == 2


def test_run_engine_success_uses_a_trusted_cwd_empty_config_and_sanitised_copy(tmp_path):
    work = tree(tmp_path)
    seen = {}

    def snoop(cmd, kw):
        if "--version" not in cmd:
            scan_dir = cmd[cmd.index("-d") + 1]
            seen["files"] = sorted(os.listdir(scan_dir))
            seen["config"] = open(cmd[cmd.index("--config-file") + 1], encoding="utf-8").read()
            seen["cwd_files"] = os.listdir(kw["cwd"])

    record = []
    out = run_engine("checkov", work, popen=fake_popen(json.dumps(CHECKOV).encode(), record=record, snoop=snoop), which=lambda n: "/usr/bin/" + n)
    assert out.status == "ok" and out.version == "checkov 3.2.1" and len(out.findings) == 3
    cmd, kw = record[-1]
    assert kw["shell"] is False and kw["stdin"] == subprocess.DEVNULL and kw["stderr"] == subprocess.DEVNULL
    assert kw["cwd"] != work and not kw["cwd"].startswith(work) and kw["env"]["HOME"].startswith(kw["cwd"])
    assert cmd[cmd.index("-d") + 1] != work and "AWS_SECRET_ACCESS_KEY" not in kw["env"]
    assert seen["files"] == ["main.tf", "sub"] and seen["config"].strip() == "{}"           # no .checkov.yaml, no evil.py
    assert ".checkov.yaml" not in seen["cwd_files"] and "main.tf" not in seen["cwd_files"]  # cwd is the trusted dir, not the upload
    trivy = []
    run_engine("trivy", work, popen=fake_popen(json.dumps(TRIVY).encode(), 0, b"Version: 0.58.0\n", record=trivy), which=lambda n: "x")
    assert trivy[-1][0][:2] == ["trivy", "--config"]


def test_run_engine_never_reports_missing_or_broken_tools_as_clean(tmp_path, monkeypatch):
    w = str(tmp_path)
    assert run_engine("checkov", w, which=lambda n: None).status == "unavailable"
    assert run_engine("nope", w).status == "failed"
    which = lambda n: "/x"
    assert run_engine("checkov", w, popen=fake_popen(b"", 0), which=which).error == "exit code 0"
    assert run_engine("checkov", w, popen=fake_popen(b"{}", 2), which=which).error == "exit code 2"
    assert run_engine("checkov", w, popen=fake_popen(b"{not json", 1), which=which).error.startswith("unreadable output")

    def oserror(cmd, **kw):
        raise PermissionError("denied")

    assert run_engine("trivy", w, popen=oserror, which=which).error == "could not start: PermissionError"
    assert run_engine("trivy", w, popen=fake_popen(json.dumps(TRIVY).encode(), 0, b""), which=which).version == ""


def test_output_is_capped_while_reading_and_the_process_is_killed(tmp_path, monkeypatch):
    monkeypatch.setattr(scanners, "MAX_OUTPUT_BYTES", 10)
    procs = []

    def popen(cmd, **kw):
        p = FakeProc(b"v1" if "--version" in cmd else b"x" * 1000, 1)
        procs.append(p)
        return p

    out = run_engine("checkov", str(tmp_path), popen=popen, which=lambda n: "/x")
    assert out.error == "output too large" and procs[-1].killed
    assert len(procs[-1].stdout.buf.getvalue()) == 1000                       # the fake holds 1000; only 11 were ever requested


def test_timeout_kills_the_process_and_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(scanners, "TIMEOUT_SECONDS", 0.05)
    procs = []

    def popen(cmd, **kw):
        p = FakeProc(b"v1" if "--version" in cmd else b"{}", 1, delay=0 if "--version" in cmd else 0.4)
        procs.append(p)
        return p

    out = run_engine("trivy", str(tmp_path), popen=popen, which=lambda n: "/x")
    assert out.status == "failed" and out.error == "timed out" and procs[-1].killed


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
