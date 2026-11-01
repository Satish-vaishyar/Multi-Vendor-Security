"""Acceptance tests: catalog section 11 (first rule pack), driven from source text through parser and rule engine.

NOT covered here by design: KEY-001 (profile-dependent CMK requirement), LOG-001 organisation-wide scope (needs the live
assessment, S31+), CFG-002 (needs the relationship graph, S17). They are tracked in docs/CLOUD_MODULE_RTM.md.
"""
import json

import pytest

from cloud import secret_scan
from cloud.parsers.cloudformation import parse_cloudformation
from cloud.parsers.kubernetes import parse_kubernetes
from cloud.parsers.terraform import parse_terraform
from cloud.rules.engine import evaluate
from cloud.rules.pack import load_pack

PACK = load_pack()


def verdict(resources, control_id):
    """The set of evidence states the control produced across the given resources."""
    return {f.evidence_state for f in evaluate(resources, PACK).findings if f.control_id == control_id}


def tf(text):
    r = parse_terraform([("main.tf", text)])
    assert r.errors == []
    return r.resources


SG = 'resource "aws_security_group" "s" {\n  ingress {\n    from_port = %s\n    to_port = %s\n    protocol = "%s"\n    %s = ["%s"]\n  }\n}\n'
POLICY = 'resource "aws_iam_policy" "p" {\n  policy = jsonencode(%s)\n}\n'


@pytest.mark.parametrize("case,source,control,expected", [
    ("NET-001 SSH from 0.0.0.0/0", SG % (22, 22, "tcp", "cidr_blocks", "0.0.0.0/0"), "CLOUD-NET-001", "FAIL_STATIC"),
    ("NET-001 restricted SSH passes", SG % (22, 22, "tcp", "cidr_blocks", "10.0.0.0/8"), "CLOUD-NET-001", "PASS_STATIC"),
    ("NET-002 SSH from ::/0", SG % (22, 22, "tcp", "ipv6_cidr_blocks", "::/0"), "CLOUD-NET-002", "FAIL_STATIC"),
    ("NET-003 RDP from everywhere", SG % (3389, 3389, "tcp", "cidr_blocks", "0.0.0.0/0"), "CLOUD-NET-003", "FAIL_STATIC"),
    ("NET-004 all ports / protocols", SG % (0, 0, "-1", "cidr_blocks", "0.0.0.0/0"), "CLOUD-NET-004", "FAIL_STATIC"),
    ("NET-005 public database listener", SG % (5432, 5432, "tcp", "cidr_blocks", "0.0.0.0/0"), "CLOUD-NET-005", "FAIL_STATIC"),
    ("IAM-001 public principal on a bucket policy",
     'resource "aws_s3_bucket_policy" "b" {\n  policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "*" }] })\n}\n',
     "CLOUD-IAM-001", "FAIL_STATIC"),
    ("IAM-002 wildcard administrator", POLICY % '{ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] }', "CLOUD-IAM-002", "FAIL_STATIC"),
    ("IAM-002 scoped policy passes", POLICY % '{ Statement = [{ Effect = "Allow", Action = "s3:GetObject", Resource = "arn:aws:s3:::b/*" }] }', "CLOUD-IAM-002", "PASS_STATIC"),
    ("IAM-003 unrestricted role trust",
     'resource "aws_iam_role" "r" {\n  assume_role_policy = jsonencode({ Statement = [{ Effect = "Allow", Principal = { AWS = "*" }, Action = "sts:AssumeRole" }] })\n}\n',
     "CLOUD-IAM-003", "FAIL_STATIC"),
    ("IAM-003 dynamic policy is UNKNOWN, never pass",
     'resource "aws_iam_role" "r" {\n  assume_role_policy = data.aws_iam_policy_document.t.json\n}\n', "CLOUD-IAM-003", "UNKNOWN_STATIC"),
    ("STO-001 S3 public access protections disabled",
     'resource "aws_s3_bucket_public_access_block" "b" {\n  block_public_acls = false\n  block_public_policy = false\n  ignore_public_acls = false\n  restrict_public_buckets = false\n}\n',
     "CLOUD-STO-001", "FAIL_STATIC"),
    ("STO-001 GCP bucket readable by allUsers",
     'resource "google_storage_bucket_iam_member" "r" {\n  role = "roles/storage.objectViewer"\n  member = "allUsers"\n}\n', "CLOUD-STO-001", "FAIL_STATIC"),
    ("STO-001 OCI public bucket", 'resource "oci_objectstorage_bucket" "b" {\n  access_type = "ObjectRead"\n}\n', "CLOUD-STO-001", "FAIL_STATIC"),
    ("STO-001 OCI private bucket", 'resource "oci_objectstorage_bucket" "b" {\n  access_type = "NoPublicAccess"\n}\n', "CLOUD-STO-001", "PASS_STATIC"),
    ("STO-002 unencrypted volume", 'resource "aws_ebs_volume" "v" {\n  encrypted = false\n}\n', "CLOUD-STO-002", "FAIL_STATIC"),
    ("STO-002 volume with omitted flag is UNKNOWN (account default may apply)", 'resource "aws_ebs_volume" "v" {\n  size = 8\n}\n', "CLOUD-STO-002", "UNKNOWN_STATIC"),
    ("STO-003 Azure storage HTTPS-only disabled",
     'resource "azurerm_storage_account" "s" {\n  https_traffic_only_enabled = false\n  min_tls_version = "TLS1_0"\n}\n', "CLOUD-STO-003", "FAIL_STATIC"),
    ("STO-003 weak minimum TLS", 'resource "azurerm_storage_account" "s" {\n  min_tls_version = "TLS1_0"\n}\n', "CLOUD-STO-004", "FAIL_STATIC"),
    ("DB-001 public managed database", 'resource "aws_db_instance" "d" {\n  publicly_accessible = true\n}\n', "CLOUD-DB-001", "FAIL_STATIC"),
    ("DB-001 provider default is private", 'resource "aws_db_instance" "d" {\n  engine = "postgres"\n}\n', "CLOUD-DB-001", "PASS_STATIC"),
    ("DB-002 unencrypted database", 'resource "aws_db_instance" "d" {\n  engine = "postgres"\n}\n', "CLOUD-DB-002", "FAIL_STATIC"),
    ("LOG-002 trail without log validation", 'resource "aws_cloudtrail" "t" {\n  name = "t"\n}\n', "CLOUD-LOG-002", "FAIL_STATIC"),
    ("CFG-001 dynamic expression hides the property", 'resource "aws_ebs_volume" "v" {\n  encrypted = var.enc\n}\n', "CLOUD-STO-002", "UNKNOWN_STATIC"),
    ("CFG-001 dynamic ingress block hides every rule", 'resource "aws_security_group" "s" {\n  dynamic "ingress" {\n    for_each = var.r\n    content { from_port = 1 }\n  }\n}\n',
     "CLOUD-NET-001", "UNKNOWN_STATIC"),
])
def test_cat11_terraform_cases(case, source, control, expected):
    assert verdict(tf(source), control) == {expected}, case


def test_cat11_cloudformation_cases():
    r = parse_cloudformation("aws.yaml", """\
Resources:
  OpenSsh:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - {IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: 0.0.0.0/0}
  PublicBucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration: {BlockPublicAcls: false, IgnorePublicAcls: false, BlockPublicPolicy: false, RestrictPublicBuckets: false}
""").resources
    assert verdict(r, "CLOUD-NET-001") == {"FAIL_STATIC"} and verdict(r, "CLOUD-STO-001") == {"FAIL_STATIC"}


def test_cat11_kubernetes_cases():
    r = parse_kubernetes("k8s.yaml", """\
apiVersion: v1
kind: Pod
metadata: {name: do-not-deploy-privileged, namespace: default}
spec:
  hostNetwork: true
  containers:
    - name: test
      image: nginx:latest
      securityContext: {privileged: true, allowPrivilegeEscalation: true, runAsUser: 0, capabilities: {add: [ALL]}}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-all, namespace: default}
spec: {podSelector: {}, policyTypes: [Ingress, Egress], ingress: [{}], egress: [{}]}
""").resources
    for control in ("CLOUD-K8S-001", "CLOUD-K8S-002", "CLOUD-K8S-003", "CLOUD-K8S-004", "CLOUD-K8S-005", "CLOUD-K8S-007", "CLOUD-K8S-008"):
        assert verdict(r, control) == {"FAIL_STATIC"}, control


def test_cat11_embedded_secret_is_reported_and_masked():
    key = "AK" + "IAQWERTYUIOPASDFGH"
    text = f'provider "aws" {{\n  access_key = "{key}"\n}}\n'
    found = secret_scan.scan_text("main.tf", text, b"salt")
    assert [f.rule_id for f in found] == ["SEC-AWS-KEY-ID"] and key not in json.dumps([f.__dict__ for f in found])
    assert key not in secret_scan.redact(text)


def test_cat11_secure_fixture_has_no_failures():
    secure = tf('''
resource "aws_security_group" "s" {
  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
resource "aws_s3_bucket_public_access_block" "b" {
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
resource "aws_db_instance" "d" {
  publicly_accessible = false
  storage_encrypted = true
}
''')
    result = evaluate(secure, PACK)
    assert result.findings and {f.evidence_state for f in result.findings} == {"PASS_STATIC"}
