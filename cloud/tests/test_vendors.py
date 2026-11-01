"""Vultr, IBM Cloud and UpCloud firewall rules, and cloud-init rules (RTM S27/S28/S29). Attribute semantics: docs/CLOUD_PROVIDER_SOURCES.md."""
import json

import pytest

from cloud import pipeline
from cloud.ir import Unknown
from cloud.parsers import cloudinit


def run(tmp_path, text, name="main.tf"):
    return pipeline.run_scan(text.encode(), name, tmp_path, salt=b"s")


def state(rep, address, control="CLOUD-NET-001"):
    return {f["resource_address"]: f["evidence_state"] for f in rep["findings"] if f["control_id"] == control}.get(address)


def tf(rtype, body):
    return 'resource "%s" "r" {\n%s\n}\n' % (rtype, body)


@pytest.mark.parametrize("body,expected", [
    ('ip_type = "v4"\n protocol = "tcp"\n subnet = "0.0.0.0"\n subnet_size = 0\n port = "22"', "FAIL_STATIC"),
    ('protocol = "tcp"\n subnet = "10.0.0.0"\n subnet_size = 8\n port = "22"', "PASS_STATIC"),
    ('protocol = "tcp"\n subnet = "0.0.0.0"\n subnet_size = 0\n port = "20:30"', "FAIL_STATIC"),
    ('protocol = "tcp"\n subnet = "0.0.0.0"\n subnet_size = 0\n port = "443"', "PASS_STATIC"),
    ('protocol = "tcp"\n subnet = "0.0.0.0"\n subnet_size = 0', "UNKNOWN_STATIC"),
    ('protocol = "icmp"\n subnet = "0.0.0.0"\n subnet_size = 0', "PASS_STATIC"),
    ('protocol = "tcp"\n subnet = "0.0.0.0"\n subnet_size = 0\n port = "22"\n source = "cloudflare"', "UNKNOWN_STATIC"),
    ('protocol = "tcp"\n subnet = "0.0.0.0"\n subnet_size = 0\n port = "22"\n source = ""', "FAIL_STATIC"),
    ('protocol = "tcp"\n subnet = "not-an-ip"\n subnet_size = 8\n port = "22"', "UNKNOWN_STATIC"),
    ('protocol = "tcp"\n subnet = "0.0.0.0"\n subnet_size = "x"\n port = "22"', "UNKNOWN_STATIC"),
    ('protocol = "tcp"\n subnet_size = 0\n port = "22"', "UNKNOWN_STATIC"),
    ('protocol = "tcp"\n subnet = var.net\n subnet_size = 0\n port = "22"', "UNKNOWN_STATIC"),
])
def test_vultr_firewall_rule(tmp_path, body, expected):
    assert state(run(tmp_path, tf("vultr_firewall_rule", body)), "vultr_firewall_rule.r") == expected


def test_vultr_ipv6_world_is_public_ssh_v6(tmp_path):
    rep = run(tmp_path, tf("vultr_firewall_rule", 'ip_type = "v6"\n protocol = "tcp"\n subnet = "::"\n subnet_size = 0\n port = "22"'))
    assert state(rep, "vultr_firewall_rule.r", "CLOUD-NET-002") == "FAIL_STATIC"


@pytest.mark.parametrize("body,expected", [
    ('direction = "inbound"\n remote = "0.0.0.0/0"\n protocol = "tcp"\n port_min = 22\n port_max = 22', "FAIL_STATIC"),
    ('direction = "inbound"\n remote = "10.0.0.0/8"\n protocol = "tcp"\n port_min = 22\n port_max = 22', "PASS_STATIC"),
    ('direction = "inbound"\n remote = "0.0.0.0/0"\n protocol = "tcp"\n port_min = 443\n port_max = 443', "PASS_STATIC"),
    ('direction = "inbound"\n remote = "0.0.0.0/0"', "FAIL_STATIC"),
    ('direction = "ingress"\n remote = "0.0.0.0/0"\n protocol = "any"', "FAIL_STATIC"),
    ('direction = "inbound"\n remote = "0.0.0.0/0"\n protocol = "icmp_tcp_udp"', "FAIL_STATIC"),
    ('direction = "inbound"\n remote = "0.0.0.0/0"\n protocol = "icmp"\n type = 8', "PASS_STATIC"),
    ('direction = "outbound"\n remote = "0.0.0.0/0"', "PASS_STATIC"),
    ('direction = "egress"\n remote = "0.0.0.0/0"', "PASS_STATIC"),
    ('direction = "sideways"\n remote = "0.0.0.0/0"', "UNKNOWN_STATIC"),
    ('remote = "0.0.0.0/0"', "UNKNOWN_STATIC"),
    ('direction = "inbound"', "UNKNOWN_STATIC"),
    ('direction = "inbound"\n remote = "r006-5e2c8f27-aaaa"\n protocol = "tcp"\n port_min = 22\n port_max = 22', "UNKNOWN_STATIC"),
    ('direction = "inbound"\n remote = "0.0.0.0/0"\n protocol = "tcp"', "UNKNOWN_STATIC"),
    ('direction = "inbound"\n remote = "0.0.0.0/0"\n tcp {\n port_min = 22\n port_max = 22\n }', "FAIL_STATIC"),
    ('direction = "inbound"\n remote = "0.0.0.0/0"\n udp {\n port_min = 22\n port_max = 22\n }', "PASS_STATIC"),
    ('direction = "inbound"\n remote = "0.0.0.0/0"\n icmp {\n type = 8\n }', "PASS_STATIC"),
])
def test_ibm_security_group_rule(tmp_path, body, expected):
    assert state(run(tmp_path, tf("ibm_is_security_group_rule", body)), "ibm_is_security_group_rule.r") == expected


def rule(**kw):
    return "firewall_rule {\n" + "".join(f' {k} = "{v}"\n' for k, v in kw.items()) + "}\n"


DROP_ALL = rule(action="drop", direction="in")
UP = [
    (rule(action="accept", direction="in", protocol="tcp", destination_port_start="22", destination_port_end="22") + DROP_ALL, "FAIL_STATIC"),
    (rule(action="accept", direction="in", protocol="tcp", destination_port_start="22", destination_port_end="22",
          source_address_start="10.0.0.0", source_address_end="10.255.255.255", family="IPv4") + DROP_ALL, "PASS_STATIC"),
    (rule(action="accept", direction="in", protocol="tcp", destination_port_start="22", destination_port_end="22",
          source_address_start="10.0.0.0", source_address_end="10.255.255.255"), "UNKNOWN_STATIC"),
    (rule(action="accept", direction="in", protocol="tcp", destination_port_start="22", destination_port_end="22"), "FAIL_STATIC"),
    (rule(action="accept", direction="in", family="IPv6") + DROP_ALL, "PASS_STATIC"),      # IPv6 only: not the IPv4 SSH check
    (rule(action="accept", direction="in") + DROP_ALL, "FAIL_STATIC"),
    (DROP_ALL + rule(action="accept", direction="in"), "PASS_STATIC"),
    (rule(action="accept", direction="out") + DROP_ALL, "PASS_STATIC"),
    (rule(action="drop", direction="in", protocol="tcp") + rule(action="accept", direction="in", protocol="tcp",
         destination_port_start="443", destination_port_end="443") + DROP_ALL, "PASS_STATIC"),
    (rule(action="accept", direction="in", protocol="tcp", destination_port_start="22") + DROP_ALL, "UNKNOWN_STATIC"),
    (rule(action="accept", direction="in", source_address_start="1.2.3.4") + DROP_ALL, "UNKNOWN_STATIC"),
    (rule(action="accept", direction="in", source_address_start="x", source_address_end="y") + DROP_ALL, "UNKNOWN_STATIC"),
    (rule(action="accept", direction="in", source_address_start="1.0.0.1", source_address_end="200.0.0.7") + DROP_ALL, "UNKNOWN_STATIC"),
    (rule(action="reject", direction="in") + DROP_ALL, "UNKNOWN_STATIC"),
    (rule(direction="in") + DROP_ALL, "UNKNOWN_STATIC"),
    (rule(action="accept") + DROP_ALL, "UNKNOWN_STATIC"),
    (rule(action="accept", direction="in", destination_port_start="${var.p}", destination_port_end="22") + DROP_ALL, "UNKNOWN_STATIC"),
    ("firewall_rule = var.rules\n", "UNKNOWN_STATIC"),
    ("firewall_rule = [1]\n", "UNKNOWN_STATIC"),
    ("", "UNKNOWN_STATIC"),
]


@pytest.mark.parametrize("body,expected", UP)
def test_upcloud_firewall_rules(tmp_path, body, expected):
    assert state(run(tmp_path, tf("upcloud_firewall_rules", 'server_id = "x"\n' + body)), "upcloud_firewall_rules.r") == expected


CI = """#cloud-config
ssh_pwauth: true
password: hunter2-secret-value
users:
  - name: ops
    plain_text_passwd: s3cretPassw0rd
    sudo: ALL=(ALL) NOPASSWD:ALL
  - default
  - not-a-dict
chpasswd:
  users:
    - {name: ops, password: abc, type: text}
runcmd:
  - [sh, -c, "curl -fsSL https://example.com/i.sh | sudo bash"]
  - echo done
write_files:
  - {path: /etc/app.conf, content: "token=abc", permissions: "0600"}
  - not-a-dict
"""
GOOD = """#cloud-config
ssh_pwauth: false
users:
  - name: ops
    sudo: ALL=(ALL) ALL
    ssh_authorized_keys: [ssh-ed25519 AAAA]
chpasswd: {expire: true, users: [{name: ops, password: "$6$hash"}]}
runcmd:
  - systemctl restart app
write_files: nope
"""


def ci_states(rep):
    return {f["control_id"]: f["evidence_state"] for f in rep["findings"] if f["control_id"].startswith("CLOUD-INIT")}


def test_cloud_init_bad_and_good(tmp_path):
    rep = run(tmp_path, CI, "user-data.yaml")
    assert rep["coverage"]["formats"] == {"cloud_init": 1}
    assert ci_states(rep) == {f"CLOUD-INIT-00{i}": "FAIL_STATIC" for i in (1, 2, 3, 4)}
    blob = json.dumps(rep)
    assert "hunter2-secret-value" not in blob and "s3cretPassw0rd" not in blob and "token=abc" not in blob
    good = ci_states(run(tmp_path / "g", GOOD, "user-data.yaml")) if (tmp_path / "g").mkdir() is None else None
    assert good == {"CLOUD-INIT-001": "PASS_STATIC", "CLOUD-INIT-002": "PASS_STATIC", "CLOUD-INIT-003": "PASS_STATIC", "CLOUD-INIT-004": "PASS_STATIC"}


@pytest.mark.parametrize("doc,expected", [
    ("ssh_pwauth: 'yes'", "FAIL_STATIC"), ("ssh_pwauth: no", "PASS_STATIC"), ("ssh_pwauth: unchanged", "UNKNOWN_STATIC"), ("packages: [git]", "UNKNOWN_STATIC")])
def test_cloud_init_ssh_pwauth(tmp_path, doc, expected):
    assert ci_states(run(tmp_path, "#cloud-config\n" + doc + "\n", "u.yaml"))["CLOUD-INIT-001"] == expected


@pytest.mark.parametrize("doc,control,expected", [
    ("chpasswd:\n  list: |\n    ops:pw", "CLOUD-INIT-002", "FAIL_STATIC"),
    ("chpasswd: nope", "CLOUD-INIT-002", "PASS_STATIC"),
    ("users:\n  - {name: a, sudo: [ALL=(ALL) NOPASSWD:ALL]}", "CLOUD-INIT-003", "FAIL_STATIC"),
    ("runcmd:\n  - wget -qO- https://x.example/i | sh", "CLOUD-INIT-004", "FAIL_STATIC"),
    ("runcmd:\n  - curl -o /tmp/x https://x.example/i", "CLOUD-INIT-004", "PASS_STATIC"),
])
def test_cloud_init_other_rules(tmp_path, doc, control, expected):
    assert ci_states(run(tmp_path, "#cloud-config\n" + doc + "\n", "u.yaml"))[control] == expected


def test_cloud_init_parser_edges():
    assert cloudinit.parse_cloud_init("u.yaml", "#cloud-config\n{unclosed").errors
    assert cloudinit.parse_cloud_init("u.yaml", "#cloud-config\n- a\n").errors
    deep = "#cloud-config\nruncmd: " + "[" * 30 + "1" + "]" * 30 + "\n"
    assert "[REDACTED]" in json.dumps(cloudinit.parse_cloud_init("u.yaml", deep).resources[0].properties)
    r = cloudinit.parse_cloud_init("", "#cloud-config\npassword: ''\n")
    assert r.resources[0].properties["password"] == "" and isinstance(r.resources[0].properties["write_files"], list)
    assert not isinstance(r.resources[0].properties["write_files"], Unknown)


def test_upcloud_ipv6_catch_all_is_public_ssh_v6(tmp_path):
    body = 'server_id = "x"\n' + rule(action="accept", direction="in", family="IPv6") + DROP_ALL
    assert state(run(tmp_path, tf("upcloud_firewall_rules", body)), "upcloud_firewall_rules.r", "CLOUD-NET-002") == "FAIL_STATIC"


@pytest.mark.parametrize("attr", ["source_address_start = var.a", "family = var.f"])
def test_upcloud_computed_source_or_family_is_unknown(tmp_path, attr):
    body = 'server_id = "x"\nfirewall_rule {\n action = "accept"\n direction = "in"\n %s\n}\n' % attr + DROP_ALL
    assert state(run(tmp_path, tf("upcloud_firewall_rules", body)), "upcloud_firewall_rules.r") == "UNKNOWN_STATIC"


def test_cloud_init_keeps_only_assessed_modules_and_masks_nested_secrets():
    text = ("#cloud-config\nssh_pwauth: false\nwrite_files: []\nrh_subscription: {activation-key: AK-123, org: o}\n"
            "users:\n  - {name: a, ssh_authorized_keys: [ssh-ed25519 AAAA], api_token: tok-1}\n")
    props = cloudinit.parse_cloud_init("u.yaml", text).resources[0].properties
    assert "rh_subscription" not in props and props["modules_present"] == ["rh_subscription"]
    assert props["users"][0]["ssh_authorized_keys"] == "[REDACTED]" and props["users"][0]["api_token"] == "[REDACTED]"
    assert props["users"][0]["name"] == "a" and "AK-123" not in json.dumps(props)


def test_upcloud_ipv6_only_drop_is_not_a_catch_all_for_ipv4(tmp_path):
    body = ('server_id = "x"\n' + rule(action="drop", direction="in", family="IPv6")
            + rule(action="accept", direction="in", protocol="tcp", destination_port_start="22", destination_port_end="22", family="IPv4") + DROP_ALL)
    assert state(run(tmp_path, tf("upcloud_firewall_rules", body)), "upcloud_firewall_rules.r") == "FAIL_STATIC"


def test_cloud_init_runcmd_strings_are_redacted():
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    text = f"#cloud-config\nruncmd:\n  - aws configure set aws_access_key_id {key}\n"
    assert key not in json.dumps(cloudinit.parse_cloud_init("u.yaml", text).resources[0].properties)
