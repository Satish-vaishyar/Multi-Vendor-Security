import io
import json
import zipfile

from fastapi.testclient import TestClient

from cloud import pipeline, scanners
from cloud.intake import Limits
from cloud.service import app

KEY = "AK" + "IAQWERTYUIOPASDFGH"
TF = '''resource "aws_security_group" "web" {
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
provider "aws" {
  access_key = "%s"
}
''' % KEY
CFN = "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      PublicAccessBlockConfiguration: {BlockPublicAcls: false, IgnorePublicAcls: false, BlockPublicPolicy: false, RestrictPublicBuckets: false}\n"
K8S = "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: d}\nspec:\n  containers:\n    - name: a\n      image: nginx:latest\n      securityContext: {privileged: true}\n"


def zipped(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_mixed_upload_runs_end_to_end(tmp_path):
    data = zipped({"infra/main.tf": TF, "cfn/t.yaml": CFN, "k8s/p.yaml": K8S, "notes.txt": "hello", "bad.pem": "x"})
    rep = pipeline.run_scan(data, "bundle.zip", tmp_path, salt=b"s")
    assert rep["status"] == "COMPLETED" and rep["mode"] == "static" and rep["input"]["filename"] == "bundle.zip"
    ids = {(f["control_id"], f["evidence_state"]) for f in rep["findings"]}
    assert ("CLOUD-NET-001", "FAIL_STATIC") in ids and ("CLOUD-STO-001", "FAIL_STATIC") in ids
    assert ("CLOUD-K8S-001", "FAIL_STATIC") in ids and ("CLOUD-SEC-001", "FAIL_STATIC") in ids
    cov = rep["coverage"]
    assert cov["providers"] == ["aws", "kubernetes"] and cov["formats"]["terraform_hcl"] == 1 and cov["files_rejected"] == 1
    assert cov["unsupported_formats"] == {"unknown": 1} and "live cloud state" in cov["not_assessed"]
    assert {"path": "bad.pem", "reason": "looks like a credential file"} in rep["rejected"]
    assert rep["summary"]["failed_by_severity"]["HIGH"] >= 3
    low = rep["statement"].lower()
    assert "violation(s) detected" in low and "live cloud state" in low
    assert "compliant" not in low and "certified" not in low and "fully secure" not in low


def test_secrets_are_masked_everywhere_in_the_report(tmp_path):
    in_resource = TF + 'resource "aws_instance" "i" {\n  user_data = "export KEY=%s"\n}\n' % KEY
    rep = pipeline.run_scan(in_resource.encode(), "main.tf", tmp_path, salt=b"s")
    assert KEY not in json.dumps(rep)                              # not in findings, resources, provider_raw, anywhere
    sec = next(f for f in rep["findings"] if f["control_id"] == "CLOUD-SEC-001")
    assert sec["evidence"][0]["preview"].startswith("AK***") and sec["source"]["line_start"] == 10
    assert "[REDACTED]" in json.dumps(rep["resources"])


def test_clean_scan_statement_never_claims_compliance(tmp_path):
    rep = pipeline.run_scan(b'resource "aws_security_group" "s" {}\n', "ok.tf", tmp_path)
    assert rep["summary"]["failed_by_severity"] == {} and rep["statement"].startswith("No violations detected in the uploaded files")
    assert "not assessed" in rep["statement"]
    unk = pipeline.run_scan(b'resource "aws_ebs_volume" "v" {\n  encrypted = var.e\n}\n', "u.tf", tmp_path / "u")
    assert "could not be determined" in unk["statement"] and unk["summary"]["states"]["UNKNOWN_STATIC"] >= 1


def test_refused_uploads_report_nothing_assessed(tmp_path):
    rep = pipeline.run_scan(b"", "a.tf", tmp_path)
    assert rep["status"] == "REJECTED" and rep["findings"] == [] and "Nothing was assessed" in rep["statement"]
    bomb = pipeline.run_scan(zipped({"a.tf": "A" * 100000}), "b.zip", tmp_path / "b", limits=Limits(max_ratio=5))
    assert bomb["status"] == "REJECTED" and "compression ratio" in bomb["error"]


def test_non_text_files_are_reported(tmp_path):
    rep = pipeline.run_scan(zipped({"latin.tf": b"\xff\xfe resource", "ok.tf": 'resource "t_x" "a" {}\n'}), "z.zip", tmp_path)
    assert {"path": "latin.tf", "reason": "not valid UTF-8 text"} in rep["rejected"] and rep["coverage"]["files_not_text"] == 1
    assert rep["summary"]["resources"] == 1


def test_plan_state_and_unresolved_modules_are_reported(tmp_path):
    plan = {"format_version": "1.2", "planned_values": {"root_module": {"resources": [
        {"address": "aws_ebs_volume.v", "type": "aws_ebs_volume", "name": "v", "values": {"encrypted": False}}]}}}
    state = {"terraform_version": "1.5", "serial": 1, "lineage": "x", "resources": [
        {"type": "aws_ebs_volume", "name": "s", "instances": [{"attributes": {"encrypted": False}}]}]}
    files = {"plan.json": json.dumps(plan), "terraform.tfstate": json.dumps(state), "m.tf": 'module "r" { source = "hashicorp/x/aws" }\n'}
    rep = pipeline.run_scan(zipped(files), "p.zip", tmp_path, salt=b"s")
    assert any(f["control_id"] == "CLOUD-STO-002" and f["resource_address"] == "aws_ebs_volume.v" for f in rep["findings"])
    assert not any(r["address"] == "aws_ebs_volume.s" for r in rep["resources"])            # state was refused at intake
    assert rep["coverage"]["modules_not_resolved"] == 1 and rep["unresolved"][0]["module"] == "module.r"
    on = pipeline.run_scan(zipped({"terraform.tfstate": json.dumps(state)}), "s.zip", tmp_path / "s", allow_state=True, salt=b"s")
    assert any(r["address"] == "aws_ebs_volume.s" for r in on["resources"])


def test_external_engines_are_optional_and_never_faked(tmp_path, monkeypatch):
    rep = pipeline.run_scan(TF.encode(), "main.tf", tmp_path, salt=b"s", engines=["nope"])
    assert rep["coverage"]["external_engines"][0]["status"] == "failed"
    monkeypatch.setattr(scanners, "run_engine", lambda name, wd: scanners.EngineRun(name, "ok", "9.9", [scanners.Finding(
        "EXT-X-1", "t", "LOW", "FAIL_STATIC", "a", "t", "p", [], {"file": "main.tf"})]))
    merged = pipeline.run_scan(TF.encode(), "main.tf", tmp_path / "e", salt=b"s", engines=["checkov"])
    assert any(f["control_id"] == "EXT-X-1" for f in merged["findings"]) and merged["coverage"]["external_engines"][0]["findings"] == 1


def test_invalid_parsed_resources_and_report_caps(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "MAX_RESOURCES_IN_REPORT", 1)
    rep = pipeline.run_scan(b'resource "t_x" "a" {}\nresource "t_x" "b" {}\n', "m.tf", tmp_path)
    assert len(rep["resources"]) == 1 and rep["summary"]["resources"] == 2
    monkeypatch.setattr(pipeline, "validate_resource", lambda r: ["missing provider"])
    bad = pipeline.run_scan(b'resource "t_x" "a" {}\n', "m.tf", tmp_path / "v")
    assert bad["errors"][-1]["error"].startswith("missing provider")


# ------------------------------------------------------------------ HTTP service
def test_scan_endpoint_requires_the_flag(monkeypatch):
    client = TestClient(app)
    monkeypatch.delenv("CLOUD_MODULE_ENABLED", raising=False)
    assert client.post("/scan", content=TF.encode()).status_code == 503
    monkeypatch.setenv("CLOUD_MODULE_ENABLED", "true")
    out = client.post("/scan", content=TF.encode(), headers={"X-Filename": "main.tf"})
    assert out.status_code == 200 and out.json()["status"] == "COMPLETED" and KEY not in out.text


def test_scan_endpoint_enforces_the_upload_limit(monkeypatch):
    monkeypatch.setenv("CLOUD_MODULE_ENABLED", "true")
    monkeypatch.setattr("cloud.service.intake.Limits", lambda: Limits(max_compressed=50))
    client = TestClient(app)
    assert client.post("/scan", content=b"x" * 51).status_code == 413            # declared Content-Length

    def chunks():
        yield b"x" * 40
        yield b"x" * 40
    assert client.post("/scan", content=chunks()).status_code == 413              # streamed without a length
    ok = client.post("/scan", content=b'resource "t_x" "a" {}\n', headers={"X-Filename": "m.tf", "X-Allow-State": "TRUE"})
    assert ok.status_code == 200
