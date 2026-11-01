"""RTM S29 / S28 additions: OpenStack Heat, Ansible ec2_group, Pulumi export, OVH IP firewall."""
import json

import pytest

from cloud import detect, pipeline
from cloud.ir import Ref, Unknown
from cloud.parsers import ansible, heat, pulumi

HEAT = """heat_template_version: 2018-08-31
parameters:
  cidr: {type: string, default: 0.0.0.0/0}
  nodefault: {type: string}
resources:
  open_ssh:
    type: OS::Neutron::SecurityGroup
    properties:
      rules:
        - {direction: ingress, protocol: tcp, port_range_min: 22, port_range_max: 22, remote_ip_prefix: {get_param: cidr}}
  closed:
    type: OS::Neutron::SecurityGroup
    properties:
      rules:
        - {protocol: tcp, port_range_min: 22, port_range_max: 22, remote_ip_prefix: 10.0.0.0/8}
  computed:
    type: OS::Neutron::SecurityGroup
    condition: prod
    properties:
      rules:
        - {protocol: tcp, port_range_min: 22, port_range_max: 22, remote_ip_prefix: {get_param: nodefault}}
  server:
    type: OS::Nova::Server
    properties:
      networks: [{port: {get_resource: p}}]
      user_data: {str_replace: {template: x, params: {a: b}}}
      flavor: {get_param: [cidr]}
      other: {get_resource: [1]}
      deep: {get_attr: [a, b]}
"""


def states(report, control):
    return sorted((f["resource_address"], f["evidence_state"]) for f in report["findings"] if f["control_id"] == control)


def test_heat_security_group_rules_are_assessed(tmp_path):
    rep = pipeline.run_scan(HEAT.encode(), "stack.yaml", tmp_path, salt=b"s")
    assert rep["coverage"]["formats"] == {"heat": 1}
    by = dict(states(rep, "CLOUD-NET-001"))
    assert by["open_ssh"] == "FAIL_STATIC" and by["closed"] == "PASS_STATIC" and by["computed"] == "UNKNOWN_STATIC"
    assert "heat" not in rep["coverage"]["unsupported_formats"]


def test_heat_intrinsics_and_errors():
    r = heat.parse_heat("s.yaml", HEAT)
    server = next(x for x in r.resources if x.logical_name == "server")
    assert isinstance(server.properties["networks"][0]["port"], Ref) and isinstance(server.properties["user_data"], Unknown)
    assert server.properties["flavor"] == "0.0.0.0/0" and isinstance(server.properties["other"], Unknown) and isinstance(server.properties["deep"], Unknown)
    assert any("condition" in n for n in next(x for x in r.resources if x.logical_name == "computed").notes)
    for bad in ("{unclosed", "- a\n", "heat_template_version: x\nresources: []\n", "heat_template_version: x\nresources: {a: 1, b: {properties: {}}}\n"):
        assert heat.parse_heat("s.yaml", bad).errors
    assert heat.parse_heat("s.yaml", "heat_template_version: x\nresources: {a: {type: T, properties: [1]}}\n").resources[0].properties == {}
    deep = "heat_template_version: x\nresources: {a: {type: T, properties: " + "[" * 45 + "1" + "]" * 45 + "}}\n"
    assert heat.parse_heat("s.yaml", deep).resources
    many = "heat_template_version: x\nresources:\n" + "".join(f"  r{i}: {{type: T}}\n" for i in range(heat.MAX_RESOURCES + 1))
    assert heat.parse_heat("s.yaml", many).truncated
    assert heat.parse_heat("s.yaml", "").errors


PLAY = """- hosts: localhost
  tasks:
    - name: open web
      amazon.aws.ec2_group:
        name: web
        rules:
          - {proto: tcp, ports: [22, '8000-8010'], cidr_ip: 0.0.0.0/0}
          - {proto: tcp, from_port: 443, to_port: 443, cidr_ip: ["10.0.0.0/8"], cidr_ipv6: "::/0"}
          - {proto: tcp, cidr_ip: 10.0.0.0/8}
          - not-a-rule
    - name: gone
      ec2_group: {name: old, state: absent}
    - name: templated
      ec2_group: {name: "{{ sg_name }}", rules: [{proto: tcp, from_port: 22, to_port: 22, cidr_ip: "{{ admin_cidr }}"}]}
    - ping:
    - block:
        - ec2_security_group: {name: nested}
      rescue: not-a-list
    - just a string
  roles: [x]
- not-a-play
"""


def test_ansible_ec2_group_maps_to_aws_rules(tmp_path):
    rep = pipeline.run_scan(PLAY.encode(), "site.yml", tmp_path, salt=b"s")
    assert rep["coverage"]["formats"] == {"ansible": 1}
    by = dict(states(rep, "CLOUD-NET-001"))
    web = next(k for k in by if k.startswith("ansible/web"))
    assert by[web] == "FAIL_STATIC"
    assert not any(k.startswith("ansible/old") for k in by)


def test_ansible_values_and_limits():
    r = ansible.parse_ansible("s.yml", PLAY)
    names = [x.logical_name for x in r.resources]
    assert "web" in names and "nested" in names and "old" not in names
    web = next(x for x in r.resources if x.logical_name == "web")
    assert [(i["from_port"], i["to_port"]) for i in web.properties["ingress"][:3]] == [(22, 22), ("8000", "8010"), (443, 443)]
    assert isinstance(next(x for x in r.resources if x.logical_name != "web" and x.properties["ingress"] and isinstance(x.properties["ingress"][0]["cidr_blocks"][0], Unknown)).properties["ingress"][0]["cidr_blocks"][0], Unknown)
    assert ansible.parse_ansible("s.yml", "{unclosed").errors
    assert ansible.parse_ansible("s.yml", "a: 1\n").resources == []
    deep = "- tasks:\n" + "".join("  " * (i + 1) + "- block:\n" for i in range(ansible.MAX_DEPTH + 3)) + "  " * (ansible.MAX_DEPTH + 4) + "- ec2_group: {name: x}\n"
    assert not any(x.logical_name == "x" for x in ansible.parse_ansible("s.yml", deep).resources)
    many = "- tasks:\n" + "".join("    - ping:\n" for _ in range(ansible.MAX_TASKS + 1))
    assert ansible.parse_ansible("s.yml", many).truncated


def export(resources):
    return json.dumps({"version": 3, "deployment": {"resources": resources}})


PSG = {"urn": "urn:pulumi:dev::p::aws:ec2/securityGroup:SecurityGroup::web", "type": "aws:ec2/securityGroup:SecurityGroup",
       "inputs": {"ingress": [{"protocol": "tcp", "fromPort": 22, "toPort": 22, "cidrBlocks": ["0.0.0.0/0"]}]}}


def test_pulumi_export_is_assessed_and_unmapped_types_are_reported(tmp_path):
    text = export([{"type": "pulumi:pulumi:Stack", "urn": "s"}, PSG, "junk",
                   {"type": "aws:s3/bucket:Bucket", "urn": "b"}, {"type": "aws:s3/bucket:Bucket", "urn": "c"}])
    assert detect.detect("stack.json", text).format == "pulumi_export"
    rep = pipeline.run_scan(text.encode(), "stack.json", tmp_path, salt=b"s")
    assert states(rep, "CLOUD-NET-001") == [(PSG["urn"], "FAIL_STATIC")]
    assert any("2 resource(s) of Pulumi type" in e["error"] for e in rep["errors"])


def test_pulumi_secrets_and_bad_input():
    secret = {"4dabf18193072939515e22adb298388d": "x", "ciphertext": "y"}
    r = pulumi.parse_pulumi("s.json", export([{**PSG, "inputs": {"description": secret, "ingress": []}}, {"type": "aws:ec2/securityGroup:SecurityGroup"},
                                               {**PSG, "inputs": []}]))
    assert isinstance(r.resources[0].properties["description"], Unknown) and r.resources[1].address == "resource-1" and r.resources[2].properties == {}
    for bad in ("{", "[]", json.dumps({"deployment": {}}), json.dumps({"deployment": {"resources": {}}})):
        assert pulumi.parse_pulumi("s.json", bad).errors
    deep = {**PSG, "inputs": {"a": json.loads("[" * 45 + "1" + "]" * 45)}}
    assert pulumi.parse_pulumi("s.json", export([deep])).resources
    big = export([PSG] * (pulumi.MAX_RESOURCES + 1))
    assert pulumi.parse_pulumi("s.json", big).truncated


@pytest.mark.parametrize("rule,state", [
    ({"action": "permit", "protocol": "tcp", "destination_port": "22"}, "FAIL_STATIC"),
    ({"action": "permit", "protocol": "tcp", "destination_port": "22", "source": "10.0.0.0/8"}, "PASS_STATIC"),
    ({"action": "deny", "protocol": "tcp", "destination_port": "22"}, "PASS_STATIC"),
    ({"protocol": "tcp", "destination_port": "22"}, "UNKNOWN_STATIC"),
])
def test_ovh_ip_firewall_rule(tmp_path, rule, state):
    body = "".join(f'  {k} = "{v}"\n' for k, v in rule.items())
    tf = 'resource "ovh_ip_firewall_rule" "r" {\n  ip = "1.2.3.4/32"\n  ip_on_firewall = "1.2.3.4"\n' + body + "}\n"
    rep = pipeline.run_scan(tf.encode(), "main.tf", tmp_path, salt=b"s")
    assert dict(states(rep, "CLOUD-NET-001")).get("ovh_ip_firewall_rule.r") == state
