import json

import pytest

from cloud import detect, yamlutil
from cloud.detect import Detection, detect as d


def test_terraform_hcl_providers_from_blocks_sources_and_resource_types():
    text = '''
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
    ibm = { source  = "IBM-Cloud/ibm" }
  }
}
provider "google" { project = "x" }
resource "azurerm_storage_account" "s" {}
data "oci_core_images" "i" {}
resource "unknown_thing" "u" {}
'''
    r = d("infra/main.tf", text)
    assert r.format == "terraform_hcl" and r.providers == ["google", "aws", "ibm", "azure", "oci"] or set(r.providers) == {"gcp", "aws", "ibm", "azure", "oci"}
    assert set(r.providers) == {"gcp", "aws", "ibm", "azure", "oci"}
    assert d("vars.tfvars", "x = 1").format == "terraform_hcl"
    assert d("a.hcl", "x = 1").providers == []


@pytest.mark.parametrize("tf_type,provider", [
    ("aws_s3_bucket", "aws"), ("alicloud_vpc", "alibaba"), ("tencentcloud_vpc", "tencent"),
    ("huaweicloud_vpc", "huawei"), ("digitalocean_droplet", "digitalocean"), ("linode_instance", "linode"),
    ("hcloud_server", "hetzner"), ("vultr_instance", "vultr"), ("ovh_cloud_project", "ovh"),
    ("scaleway_instance_server", "scaleway"), ("upcloud_server", "upcloud"), ("openstack_compute_instance_v2", "openstack"),
    ("vsphere_virtual_machine", "vmware"), ("nutanix_virtual_machine", "nutanix"), ("kubernetes_pod", "kubernetes"),
])
def test_resource_type_prefix_maps_to_provider(tf_type, provider):
    assert d("m.tf", f'resource "{tf_type}" "x" {{}}').providers == [provider]


def test_bicep_rego_chart_pulumi_cloud_init_by_name_or_marker():
    assert d("x.bicep", "param a string") == Detection("x.bicep", "bicep", ["azure"])
    assert d("x.bicepparam", "using 'main.bicep'").format == "bicep"
    assert d("p.rego", "package x").format == "rego"
    assert d("Chart.yaml", "name: x").format == "helm_chart"
    assert d("Pulumi.yaml", "name: x").format == "pulumi"
    assert d("user-data", "#cloud-config\npackages: []").format == "cloud_init"


def test_cloudformation_by_header_transform_or_resource_types():
    assert d("t.yaml", "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}").format == "cloudformation"
    assert d("t.yml", "Transform: AWS::Serverless-2016-10-31\nResources: {}").providers == ["aws"]
    assert d("t.template", "Resources:\n  B:\n    Type: AWS::S3::Bucket\n").format == "cloudformation"
    assert d("t.json", json.dumps({"Resources": {"B": {"Type": "AWS::S3::Bucket"}}})).format == "cloudformation"
    assert d("t.yaml", "Resources:\n  B:\n    Type: Custom::Thing\n").format == "unknown"
    assert d("t.yaml", "Resources:\n  B: !Ref X\n  C:\n    Type: AWS::EC2::Instance\n").format == "cloudformation"


def test_ros_heat_arm():
    assert d("r.yaml", "ROSTemplateFormatVersion: '2015-09-01'").providers == ["alibaba"]
    assert d("h.yaml", "heat_template_version: 2018-08-31").providers == ["openstack"]
    arm = {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#", "resources": []}
    assert d("a.json", json.dumps(arm)) == Detection("a.json", "arm", ["azure"])


def test_terraform_plan_state_and_json_config():
    plan = {"format_version": "1.2", "planned_values": {}, "resource_changes": [
        {"type": "aws_instance"}, {"type": "google_compute_instance"}, "junk"]}
    r = d("plan.json", json.dumps(plan))
    assert r.format == "terraform_plan" and r.providers == ["aws", "gcp"]
    assert d("p2.json", json.dumps({"format_version": "1.0", "configuration": {}})).providers == []
    st = d("s.json", json.dumps({"terraform_version": "1.5", "serial": 3, "resources": []}))
    assert st.format == "terraform_state" and "opt-in" in st.note
    tfj = {"resource": {"aws_s3_bucket": {"b": {}}}, "provider": {"aws": {}}}
    r = d("m.tf.json", json.dumps(tfj))
    assert r.format == "terraform_hcl" or r.format == "terraform_json"
    j = d("x.json", json.dumps({"provider": {"google": {}}, "terraform": {}}))
    assert j.format == "terraform_json" and j.providers == ["gcp"]
    assert d("x.json", json.dumps({"terraform": {}})).providers == []


def test_kubernetes_multi_document_and_ansible():
    docs = "kind: ConfigMap\napiVersion: v1\n---\nkind: Pod\napiVersion: v1\n"
    assert d("k.yaml", docs) == Detection("k.yaml", "kubernetes", ["kubernetes"])
    assert d("pb.yml", "- hosts: all\n  tasks:\n    - ping:\n").format == "ansible"
    assert d("pb.yml", "- name: x\n  roles: [a]\n").format == "ansible"
    assert d("l.yml", "- a\n- b\n").format == "unknown"
    assert d("l.yml", "- 1\n").format == "unknown"


def test_unknown_and_invalid_inputs_are_not_fatal():
    assert d("a.txt", "hello").format == "unknown"
    assert d("a.json", "{not json").format == "unknown"
    assert d("a.json", "[1, 2]").format == "unknown"
    assert d("a.json", json.dumps({"hello": "world"})).format == "unknown"
    bad = d("a.yaml", "a: [unclosed")
    assert bad.format == "unknown" and bad.note == "invalid YAML"
    assert d("a.yaml", "key: value").format == "unknown"
    assert d("a.yaml", "").format == "unknown"


def test_detect_all_and_providers_of_deduplicate():
    files = [{"path": "a.tf", "text": 'resource "aws_vpc" "v" {}'}, {"path": "b.tf", "text": 'provider "aws" {}'},
             {"path": "c.yaml", "text": "kind: Pod\napiVersion: v1"}]
    out = detect.detect_all(files)
    assert detect.providers_of(out) == ["aws", "kubernetes"]
    assert [x.format for x in out] == ["terraform_hcl", "terraform_hcl", "kubernetes"]


def test_yaml_loader_keeps_lines_and_tags():
    doc = yamlutil.load("Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      Name: !Sub '${X}-b'\n      Ids: !GetAtt [A, Arn]\n      M: !Transform {Name: x}\n")
    b = doc["Resources"]["B"]
    assert b["Properties"]["Name"] == {"Fn::Sub": "${X}-b"}
    assert b["Properties"]["Ids"] == {"Fn::GetAtt": ["A", "Arn"]}
    assert b["Properties"]["M"] == {"Fn::Transform": {"Name": "x"}}
    assert doc.key_lines["Resources"] == 1 and doc["Resources"].key_lines["B"] == 2
    assert yamlutil.line_of(b, "Type") == 3 and yamlutil.line_of(b) == 3
    assert yamlutil.line_of(b["Properties"]["Ids"]["Fn::GetAtt"]) == 6
    assert yamlutil.line_of("scalar") == 1 and yamlutil.line_of({}, "k", default=9) == 9
    assert yamlutil.line_of(yamlutil.LDict(), "missing") == 1


def test_yaml_loader_rejects_python_objects_and_bad_input():
    with pytest.raises(yamlutil.YamlError):
        yamlutil.load("x: !!python/object/apply:os.system ['echo hi']")
    with pytest.raises(yamlutil.YamlError):
        yamlutil.load("a: [unclosed")
    assert yamlutil.load("") is None
    assert len(yamlutil.load_all("a: 1\n---\n---\nb: 2\n")) == 2


def test_yaml_alias_bombs_and_deep_nesting_are_refused_cheaply():
    import time
    lines = ["a: &a [x,x,x,x,x,x,x,x,x]"]
    prev = "a"
    for i in range(b := 12):
        name = chr(ord("b") + i)
        lines.append(f"{name}: &{name} [*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev},*{prev}]")
        prev = name
    t0 = time.perf_counter()
    with pytest.raises(yamlutil.YamlError, match="too many nodes"):
        yamlutil.load("\n".join(lines) + "\n")
    assert time.perf_counter() - t0 < 5 and b == 12
    with pytest.raises(yamlutil.YamlError, match="too deeply"):
        yamlutil.load("[" * 150 + "]" * 150)
    with pytest.raises(yamlutil.YamlError, match="too deeply"):
        yamlutil.load("&a [*a]")                        # recursive alias
    docs = "\n---\n".join(["x: [" + ",".join(["1"] * 400) + "]"] * 30)
    assert len(yamlutil.load_all(docs)) == 30           # many ordinary documents are fine


def test_yaml_total_budget_across_documents_and_recursion_guard(monkeypatch):
    monkeypatch.setattr(yamlutil, "MAX_YAML_NODES", 100)
    with pytest.raises(yamlutil.YamlError, match="too many nodes"):
        yamlutil.load_all("\n---\n".join(["k: [" + ",".join(["1"] * 30) + "]"] * 5))
    monkeypatch.undo()
    def boom(*a, **k):
        raise RecursionError()
    monkeypatch.setattr(yamlutil, "_expanded_size", boom)
    with pytest.raises(yamlutil.YamlError, match="nested too deeply"):
        yamlutil.load("a: 1")
    monkeypatch.undo()
    small = "base: &b {x: 1}\ncopy: *b\n"
    assert yamlutil.load(small)["copy"] == {"x": 1}      # ordinary anchors still work
