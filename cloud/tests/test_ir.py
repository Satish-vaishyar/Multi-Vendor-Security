import json

from cloud import ir
from cloud.ir import Finding, Ref, Resource, Source, Unknown, jsonable, resource_to_dict, validate_resource

KEY = "AK" + "IAQWERTYUIOPASDFGH"


def make(**kw):
    base = dict(provider="aws", service="s3", resource_type="aws_s3_bucket", logical_name="b", address="aws_s3_bucket.b",
                properties={"name": "x", "secret": f"key {KEY}", "ref": Ref("aws_vpc.v.id"), "u": Unknown("computed"),
                            "n": [1, {"k": None}], "t": ("a", "b")},
                source=Source("main.tf", 3, 9, "terraform_hcl", "p"))
    base.update(kw)
    return Resource(**base).finalize()


def test_resource_record_is_json_safe_redacted_and_keyed():
    d = resource_to_dict(make(), {"region": "ap-south-1", "account_or_tenant": "123"})
    json.dumps(d)                                                   # must not raise
    assert d["resource_key"] == "aws:123:ap-south-1:aws_s3_bucket.b"
    assert d["properties"]["ref"] == {"$ref": "aws_vpc.v.id"} and d["properties"]["u"] == {"$unknown": "computed"}
    assert KEY not in json.dumps(d) and "[REDACTED]" in d["properties"]["secret"]
    assert d["source"] == {"file": "main.tf", "line_start": 3, "line_end": 9, "format": "terraform_hcl", "parser_version": "p"}
    assert d["scope"]["organization"] is None and d["unknown_fields"] == ["u"]
    assert resource_to_dict(make())["resource_key"] == "aws:-:-:aws_s3_bucket.b"


def test_jsonable_handles_every_leaf_type():
    assert jsonable({1: object.__class__}) == {"1": str(object.__class__)}
    assert jsonable([True, None, 1.5, "s"]) == [True, None, 1.5, "s"]
    assert jsonable("plain", redact=True) == "plain" and jsonable(f"k {KEY}", redact=True) == "k [REDACTED]"
    assert jsonable(f"k {KEY}") == f"k {KEY}"                       # redaction is opt-in


def test_validation():
    assert validate_resource(make()) == []
    bad = make(provider="", confidence=2, evidence_mode="x", source=Source("", 5, 2))
    assert set(validate_resource(bad)) == {"missing provider", "confidence outside 0..1", "invalid evidence_mode",
                                           "missing source file", "invalid source line range"}


def test_finding_serialisation_and_stable_dedupe_key():
    f = Finding("CLOUD-NET-001", "t", "HIGH", "FAIL_STATIC", "aws_sg.a", "aws_sg", "aws",
                [{"property": "P", "observed": Unknown("x")}], {"file": "a.tf", "line_start": 1})
    g = Finding("CLOUD-NET-001", "t", "HIGH", "PASS_STATIC", "aws_sg.a", "aws_sg", "aws", [], {"file": "a.tf"})
    assert f.dedupe_key == g.dedupe_key and len(f.dedupe_key) == 20
    d = f.to_dict()
    assert d["evidence"][0]["observed"] == {"$unknown": "x"} and d["engine"] == "orbit"
    assert ir.SEVERITIES[0] == "CRITICAL" and "UNKNOWN_STATIC" in ir.EVIDENCE_STATES
