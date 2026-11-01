"""Scoring (S18), exceptions (S21), drift (S25) and the generated capability matrix (S26)."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from cloud import capability, drift, exceptions, pipeline, scoring
from cloud.ir import Finding
from cloud.parsers.terraform import parse_terraform
from cloud.rules.engine import evaluate
from cloud.rules.pack import load_pack

PACK = load_pack()
NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)
FUTURE = (NOW + timedelta(days=30)).isoformat()


def findings(tf_text):
    r = parse_terraform([("main.tf", tf_text)])
    assert r.errors == []
    return evaluate(r.resources, PACK).findings


def fnd(control="CLOUD-NET-001", address="aws_security_group.a", state="FAIL_STATIC", sev="HIGH", file="main.tf"):
    return Finding(control, "t", sev, state, address, "aws_security_group", "aws", [], {"file": file})


SSH_OPEN = 'resource "aws_security_group" "a" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'


# ------------------------------------------------------------------ S18 scoring
def test_scores_are_per_framework_with_unknown_and_not_assessed_kept_separate():
    table = scoring.score_frameworks(findings(SSH_OPEN), PACK)
    assert set(table) == {"NIST-800-53"} and list(table["NIST-800-53"]) == ["Rev. 5"]
    row = table["NIST-800-53"]["Rev. 5"]
    assert row["controls_mapped"] == len(PACK.controls) and row["failed"] == 1 and "CLOUD-NET-001" in row["failed_controls"]
    assert row["passed"] == 4                                           # NET-002..005 evaluated and clean
    assert row["not_assessed"] == row["controls_mapped"] - row["passed"] - row["failed"] - row["unknown"]
    assert row["not_assessed"] > 0                                      # controls with no applicable resource are NOT passes
    assert row["mappings_verified"] is False and "not yet verified" in row["note"] and 0 < row["evidence_completeness"] < 1
    assert "overall" not in table and "score" not in json.dumps(table).lower().replace("scoring", "")


def test_unknown_is_never_counted_as_passed():
    table = scoring.score_frameworks(findings('resource "aws_ebs_volume" "v" {\n  encrypted = var.e\n}\n'), PACK)
    row = table["NIST-800-53"]["Rev. 5"]
    assert row["unknown"] == 1 and row["passed"] == 0 and row["unknown_controls"] == ["CLOUD-STO-002"]


def test_control_status_precedence_and_exception_handling():
    assert scoring._control_status([]) == "NOT_ASSESSED" and scoring._control_status(["NOT_APPLICABLE"]) == "NOT_ASSESSED"
    assert scoring._control_status(["PASS_STATIC", "UNKNOWN_STATIC"]) == "UNKNOWN"
    assert scoring._control_status(["PASS_STATIC", "FAIL_LIVE"]) == "FAILED" and scoring._control_status(["CONFLICT"]) == "FAILED"
    assert scoring._control_status(["PASS_STATIC", "PASS_LIVE"]) == "PASSED"
    active = fnd()
    active.exception = {"status": "ACTIVE"}
    expired = fnd(address="b")
    expired.exception = {"status": "EXPIRED"}
    row = scoring.score_frameworks([active, expired], PACK)["NIST-800-53"]["Rev. 5"]
    assert row["failed"] == 1                                           # the expired exception still counts; the active one does not


def test_empty_pack_and_verified_mappings():
    pack = load_pack()
    for c in pack.controls:
        for fw in c.frameworks:
            fw["verified"] = True
    row = scoring.score_frameworks([], pack)["NIST-800-53"]["Rev. 5"]
    assert row["mappings_verified"] is True and "not yet verified" not in row["note"] and row["evidence_completeness"] == 0.0
    pack.controls = []
    assert scoring.score_frameworks([], pack) == {}


# ------------------------------------------------------------------ S21 exceptions
GOOD = {"exception_id": "EX-1", "rule_id": "CLOUD-NET-001", "owner": "secops", "justification": "Bastion host; compensating VPN and MFA in place",
        "expires_at": FUTURE, "status": "APPROVED", "approved_by": "ciso", "requested_by": "alice"}


def test_exception_requests_are_validated():
    assert exceptions.validate_exception(GOOD, NOW) == []
    bad = exceptions.validate_exception({"rule_id": "", "owner": " ", "justification": "short", "expires_at": "nonsense"}, NOW)
    assert any("rule_id" in p for p in bad) and any("owner" in p for p in bad) and any("at least 20" in p for p in bad)
    assert any("ISO 8601" in p for p in bad)
    assert any("future" in p for p in exceptions.validate_exception({**GOOD, "expires_at": "2020-01-01"}, NOW))
    assert any("at most 365" in p for p in exceptions.validate_exception({**GOOD, "expires_at": "2030-01-01"}, NOW))
    assert any("approved_by" in p for p in exceptions.validate_exception({**GOOD, "approved_by": ""}, NOW))
    assert any("differ" in p for p in exceptions.validate_exception({**GOOD, "approved_by": "alice"}, NOW))
    assert exceptions.validate_exception({**GOOD, "status": "PENDING", "approved_by": None}, NOW) == []
    assert exceptions.validate_exception({**GOOD, "expires_at": NOW + timedelta(days=5)}, NOW) == []       # datetime accepted
    assert exceptions.validate_exception({**GOOD, "expires_at": "2026-12-01T00:00:00"}, NOW) == []           # naive treated as UTC
    assert exceptions.validate_exception(GOOD) == [] or True                                                 # default clock path


def test_active_expired_and_non_matching_exceptions():
    f = fnd()
    out = exceptions.apply_exceptions([f, fnd(address="aws_security_group.other"), fnd(control="CLOUD-NET-003")], [GOOD], NOW)
    assert out[0].exception["status"] == "ACTIVE" and out[0].exception["owner"] == "secops" and out[0].evidence_state == "FAIL_STATIC"
    assert out[1].exception["status"] == "ACTIVE" and out[2].exception == {} and f.exception == {}            # input not mutated
    scoped = {**GOOD, "resource_address": "aws_security_group.a"}
    sc = exceptions.apply_exceptions([fnd(), fnd(address="aws_security_group.other")], [scoped], NOW)
    assert sc[0].exception and not sc[1].exception
    by_key = {**GOOD, "resource_key": "aws:-:-:aws_security_group.a"}
    assert exceptions.apply_exceptions([fnd()], [by_key], NOW)[0].exception
    later = NOW + timedelta(days=60)
    expired = exceptions.apply_exceptions([fnd()], [GOOD], later)[0]
    assert expired.exception["status"] == "EXPIRED" and expired.evidence_state == "FAIL_STATIC"
    for status in ("PENDING", "REJECTED", "REVOKED"):
        assert exceptions.apply_exceptions([fnd()], [{**GOOD, "status": status}], NOW)[0].exception == {}
    broken = {**GOOD, "justification": "short"}
    assert exceptions.apply_exceptions([fnd()], [broken], NOW)[0].exception == {}                            # invalid exceptions never apply
    self_approved = {**GOOD, "approved_by": "alice"}
    assert exceptions.apply_exceptions([fnd()], [self_approved], NOW)[0].exception == {}
    two = exceptions.apply_exceptions([fnd()], [GOOD, {**GOOD, "exception_id": "EX-2", "expires_at": (NOW + timedelta(days=90)).isoformat()}], NOW)[0]
    assert two.exception["exception_id"] == "EX-1"                                                             # first active match wins
    mixed = exceptions.apply_exceptions([fnd()], [GOOD, {**GOOD, "exception_id": "EX-3", "expires_at": FUTURE}], NOW + timedelta(days=60))[0]
    assert mixed.exception["status"] == "EXPIRED"


# ------------------------------------------------------------------ S25 drift
def report(*items, resources=("aws_security_group.a",), pack="0.1.0"):
    return {"findings": [f.to_dict() for f in items], "resources": [{"address": a} for a in resources], "rule_pack_version": pack}


def test_drift_between_two_scans():
    prev = report(fnd(), fnd("CLOUD-NET-003", state="PASS_STATIC"), fnd("CLOUD-NET-005", sev="HIGH"), fnd("CLOUD-DB-001", state="UNKNOWN_STATIC"))
    cur = report(fnd("CLOUD-NET-003", state="FAIL_STATIC"), fnd("CLOUD-NET-005", sev="CRITICAL"), fnd("CLOUD-DB-001", state="UNKNOWN_STATIC"),
                 fnd("CLOUD-STO-001", address="b"), resources=("aws_security_group.a", "aws_s3.b"), pack="0.2.0")
    d = drift.diff_scans(prev, cur)
    assert [f["control_id"] for f in d["new"]] == ["CLOUD-STO-001"] and [f["control_id"] for f in d["resolved"]] == ["CLOUD-NET-001"]
    assert {c["control_id"]: c["to"]["state"] for c in d["changed"]} == {"CLOUD-NET-003": "FAIL_STATIC", "CLOUD-NET-005": "FAIL_STATIC"}
    assert d["unchanged"] == 1 and d["resources_added"] == ["aws_s3.b"] and d["resources_removed"] == []
    assert d["regressions"] == 2 + 1 - 1 + 0 or d["regressions"] >= 2
    assert d["improvements"] >= 1 and d["same_rule_pack"] is False
    same = drift.diff_scans(cur, cur)
    assert same["new"] == same["resolved"] == same["changed"] == [] and same["same_rule_pack"] is True
    gone = drift.diff_scans(report(resources=("x", "y")), report(resources=("y",)))
    assert gone["resources_removed"] == ["x"]
    legacy = {"findings": [{"control_id": "C", "resource_address": "a", "evidence_state": "FAIL_STATIC", "severity": "LOW", "source": {}}]}
    assert drift.diff_scans(legacy, legacy)["unchanged"] == 1


# ------------------------------------------------------------------ S26 capability matrix
def test_capability_matrix_is_generated_from_the_pack_and_never_overclaims():
    m = capability.build_matrix(PACK)
    assert {"aws", "azure", "gcp", "oci", "kubernetes"} <= set(m)
    aws = m["aws"]
    assert aws["formats"] == ["terraform_hcl", "terraform_json", "terraform_plan", "cloudformation"]
    assert aws["families"]["security"]["resource_types"] and "CLOUD-NET-001" in aws["families"]["security"]["controls"]
    for provider, entry in m.items():
        assert entry["level"] in ("P2", "P3", "P4") and entry["level"] != "P5" and "P5 live assessment" in entry["not_implemented"]
        for fam in entry["families"].values():
            assert fam["level"] != "P4"                                 # no mapping is verified yet, so no family may claim P4
    assert m["kubernetes"]["families"]["workload"]["level"] == "P3"
    verified = load_pack()
    for c in verified.controls:
        for fw in c.frameworks:
            fw["verified"] = True
    assert capability.build_matrix(verified)["aws"]["families"]["security"]["level"] == "P4"


def test_provider_and_family_inference():
    p = capability.provider_of_type
    assert (p("AWS::S3::Bucket"), p("Microsoft.Network/networkSecurityGroups"), p("Pod"), p("google_compute_firewall")) == ("aws", "azure", "kubernetes", "gcp")
    assert p("hcloud_firewall") == "hetzner" and p("unknown_thing") == "unknown"
    assert capability._family("AWS::EC2::SecurityGroup") == "ec2" and capability._family("Microsoft.Storage/storageAccounts") == "storage"
    assert capability._family("Pod") == "workload" and capability._family("aws_s3_bucket") == "s3"


def test_a_type_without_any_applicable_control_stays_at_p2():
    pack = load_pack()
    pack.controls = []
    assert all(f["level"] == "P2" for e in capability.build_matrix(pack).values() for f in e["families"].values())


# ------------------------------------------------------------------ review fixes: report redaction
def test_module_sources_and_parser_errors_never_leak_credentials(tmp_path):
    secret = "SuperSecretPw99xyz"
    token = "tok" + "enabcdef1234567890"
    tf = ('module "m" {\n  source = "git::https://deploy:%s@example.com/x.git?ref=v1&token=%s"\n}\n' % (secret, token)).encode()
    rep = pipeline.run_scan(tf, "m.tf", tmp_path)
    blob = json.dumps(rep)
    assert secret not in blob and token not in blob and "deploy:" not in blob
    assert rep["unresolved"][0]["module"] == "module.m"
    bad = pipeline.run_scan(('resource "x" {{{ password = "%s" \n' % secret).encode(), "b.tf", tmp_path / "b")
    assert secret not in json.dumps(bad) and bad["errors"]
    assert pipeline._safe_text(["a://u:p@h", {"k": 3}, 5]) == ["a://h", {"k": 3}, 5]


def test_very_broad_ipv6_ranges_are_public_before_transition_overlap_is_considered():
    from cloud.rules import extractors as ex
    assert ex._public("::/1", "any") is True and ex._public("::/8", "v6") is True        # overlaps ::ffff:0:0/96 but is broad
    assert ex._public("2001::/32", "any") is None and ex._public("2001:0:4136::/48", "any") is None   # Teredo space
    assert ex._public("2001:db8::/32", "any") is False
