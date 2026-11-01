import sys
from pathlib import Path

import pytest

from cloud.ir import Resource, Source, Unknown
from cloud.parsers.cloudformation import parse_cloudformation
from cloud.parsers.kubernetes import parse_kubernetes
from cloud.parsers.terraform import parse_terraform
from cloud.rules import engine
from cloud.rules.engine import eval_condition, eval_op, evaluate, evaluate_resource, map_resource
from cloud.rules.pack import load_pack

PACK = load_pack()


def resources(text, path="main.tf"):
    r = parse_terraform([(path, text)])
    assert r.errors == []
    return r.resources


# ---------------------------------------------------------------- operator parity with the network OKF engine
OPERATORS = ["EQUALS", "NOT_EQUALS", "GTE", "LTE", "GT", "LT", "IN", "NOT_IN", "CONTAINS", "EXISTS", "equals", "BOGUS"]
OBSERVED = [None, True, False, 0, 22, "2", "abc", [1, 2], {"a": 1}, 2.5]
EXPECTED = [None, True, False, 0, 22, "2", "abc", [1, 2, 22], "b", 2]


def test_operator_semantics_match_the_network_okf_engine():
    okf = Path(__file__).resolve().parents[2] / "okf"
    sys.path.insert(0, str(okf))
    try:
        from src.engines import eval_op as okf_eval_op, eval_condition as okf_eval_condition
    except Exception:                                    # pragma: no cover - okf deps unavailable in this environment
        pytest.skip("okf engine not importable here")
    finally:
        sys.path.remove(str(okf))
        for m in [m for m in sys.modules if m == "src" or m.startswith("src.")]:
            del sys.modules[m]
    for op in OPERATORS:
        for obs in OBSERVED:
            for exp in EXPECTED:
                assert eval_op(obs, op, exp) == okf_eval_op(obs, op, exp), (op, obs, exp)
    cond = {"all": [{"property": "A.B", "operator": "EQUALS", "value": True},
                    {"any": [{"property": "C", "operator": "GTE", "value": 2}, {"property": "D", "operator": "EXISTS"}]}]}
    for flat, nested in [({"A.B": True, "C": 3}, {"A": {"B": True}, "C": 3}), ({"A.B": True}, {"A": {"B": True}}),
                         ({"A.B": False}, {"A": {"B": False}}), ({}, {}), ({"A.B": True, "C": 1, "D": 1}, {"A": {"B": True}, "C": 1, "D": 1})]:
        assert eval_condition(flat, cond)[0] == okf_eval_condition(nested, cond)[0], flat


def test_condition_combinators_and_evidence():
    props = {"a": True, "b": False, "c": None}
    eq = lambda p, v: {"property": p, "operator": "EQUALS", "value": v}
    assert eval_condition(props, {"all": [eq("a", True), eq("b", False)]})[0] is True
    assert eval_condition(props, {"all": [eq("a", True), eq("b", True)]})[0] is False
    assert eval_condition(props, {"all": [eq("a", True), eq("c", True)]})[0] is None
    assert eval_condition(props, {"any": [eq("a", False), eq("b", True)]})[0] is False
    assert eval_condition(props, {"any": [eq("a", True), eq("c", True)]})[0] is True
    assert eval_condition(props, {"any": [eq("a", False), eq("c", True)]})[0] is None
    ok, ev = eval_condition(props, eq("b", False))
    assert ok is True and ev == [{"property": "b", "operator": "EQUALS", "expected": False, "observed": False, "status": "PASS"}]
    assert eval_condition(props, eq("zzz", True))[1][0]["status"] == "UNKNOWN"
    assert eval_condition(props, {"property": "a"})[0] is False                # default operator EQUALS, expected None
    assert eval_op(1, "GTE", "x") is False                                      # evaluation error is a non-match, as in OKF


# ---------------------------------------------------------------- mapping and evaluation
def test_map_resource_and_applicability():
    sg, bucket = resources('resource "aws_security_group" "s" {}\nresource "aws_s3_bucket" "b" {}\n')
    assert "NET.SG.PUBLIC_SSH_V4" in map_resource(sg, PACK) and map_resource(bucket, PACK) == {}
    assert evaluate_resource(bucket, PACK) == []                                # unsupported type: no findings at all
    assert {f.control_id for f in evaluate_resource(sg, PACK)} == {"CLOUD-NET-00%d" % i for i in range(1, 6)}


def test_findings_carry_evidence_provenance_and_remediation():
    r = resources('resource "aws_security_group" "w" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
    f = next(x for x in evaluate_resource(r[0], PACK) if x.control_id == "CLOUD-NET-001")
    assert (f.evidence_state, f.severity, f.provider, f.rule_version) == ("FAIL_STATIC", "HIGH", "aws", "1.0.0")
    assert f.source == {"file": "main.tf", "line_start": 1, "line_end": 8, "format": "terraform_hcl"}
    assert f.evidence[0]["observed"] is True and f.evidence[0]["expected"] is False and f.remediation["summary"]
    assert f.frameworks[0]["verified"] is False and f.engine == "orbit"
    assert f.to_dict()["dedupe_key"] == f.dedupe_key


def test_unknown_inputs_never_become_pass():
    r = resources('resource "aws_security_group" "w" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n    cidr_blocks = [var.cidr]\n  }\n}\n')
    states = {f.control_id: f.evidence_state for f in evaluate_resource(r[0], PACK)}
    assert states["CLOUD-NET-001"] == "UNKNOWN_STATIC" and states["CLOUD-NET-003"] == "PASS_STATIC"
    dyn = resources('resource "aws_security_group" "w" {\n  dynamic "ingress" {\n    for_each = var.r\n    content { from_port = 1 }\n  }\n}\n')
    assert {f.evidence_state for f in evaluate_resource(dyn[0], PACK)} == {"UNKNOWN_STATIC"}


def test_low_confidence_and_notes_are_surfaced():
    cfn = parse_cloudformation("a.yaml", "Resources:\n  S:\n    Type: AWS::EC2::SecurityGroup\n    Condition: C\n    Properties: {}\n").resources[0]
    note = next(iter(evaluate_resource(cfn, PACK))).notes
    assert any("conditional resource" in n for n in note) and any("reduced confidence" in n for n in note)


def test_evaluate_reports_coverage_and_skips_data_sources():
    rs = resources('data "aws_ami" "a" {}\nresource "aws_s3_bucket" "b" {}\nresource "aws_s3_bucket" "c" {}\nresource "aws_cloudtrail" "t" {}\n')
    out = evaluate(rs, PACK)
    cov = out.coverage
    assert cov["resources_parsed"] == 4 and cov["unsupported_resource_types"] == {"aws_s3_bucket": 2}
    assert cov["resources_with_supported_type"] == 2 and cov["rule_evaluations"] == len(out.findings) == 2
    assert cov["states"] == {"FAIL_STATIC": 2} and cov["pack_version"] == PACK.version and cov["rules_in_pack"] == len(PACK.controls)


def test_resource_without_any_applicable_controls_is_not_counted_as_covered():
    r = Resource("aws", "iam", "aws_iam_policy", "p", "aws_iam_policy.p", {"policy": Unknown("x")}, Source("f.tf", 1, 1))
    out = evaluate([r], PACK)
    assert out.coverage["resources_with_findings_or_passes"] == 1               # evaluated (UNKNOWN is still an evaluation)
    assert out.findings[0].evidence_state == "UNKNOWN_STATIC"
    assert "evaluate" in dir(engine)
