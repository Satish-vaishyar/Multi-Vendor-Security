import pytest

from cloud.ir import Ref, Resource, Source, Unknown
from cloud.parsers.terraform import parse_terraform
from cloud.rules import extractors as ex

SSH = "NET.SG.PUBLIC_SSH_V4"
ALL = "NET.SG.PUBLIC_ALL"


def ssh(tf):
    return ex.network_ingress(parse_terraform([("main.tf", tf)]).resources[0])


CASES = [
    # (id, terraform, expected SSH state)
    ("do open", 'resource "digitalocean_firewall" "f" {\n  inbound_rule {\n    protocol = "tcp"\n    port_range = "22"\n    source_addresses = ["0.0.0.0/0", "::/0"]\n  }\n}', True),
    ("do admin only", 'resource "digitalocean_firewall" "f" {\n  inbound_rule {\n    protocol = "tcp"\n    port_range = "22"\n    source_addresses = ["203.0.113.7/32"]\n  }\n}', False),
    ("do no sources", 'resource "digitalocean_firewall" "f" {\n  inbound_rule {\n    protocol = "tcp"\n    port_range = "22"\n  }\n}', False),
    ("do dynamic block", 'resource "digitalocean_firewall" "f" {\n  dynamic "inbound_rule" {\n    for_each = var.rules\n    content {\n      protocol = "tcp"\n    }\n  }\n}', None),
    ("linode open", 'resource "linode_firewall" "f" {\n  inbound_policy = "DROP"\n  inbound {\n    label = "ssh"\n    action = "ACCEPT"\n    protocol = "TCP"\n    ports = "22, 80"\n    ipv4 = ["0.0.0.0/0"]\n  }\n}', True),
    ("linode drop", 'resource "linode_firewall" "f" {\n  inbound_policy = "DROP"\n  inbound {\n    action = "DROP"\n    protocol = "TCP"\n    ports = "22"\n    ipv4 = ["0.0.0.0/0"]\n  }\n}', False),
    ("linode no action", 'resource "linode_firewall" "f" {\n  inbound_policy = "DROP"\n  inbound {\n    protocol = "TCP"\n    ports = "22"\n    ipv4 = ["0.0.0.0/0"]\n  }\n}', None),
    ("hetzner open", 'resource "hcloud_firewall" "f" {\n  rule {\n    direction = "in"\n    protocol = "tcp"\n    port = "22"\n    source_ips = ["0.0.0.0/0"]\n  }\n}', True),
    ("hetzner out", 'resource "hcloud_firewall" "f" {\n  rule {\n    direction = "out"\n    protocol = "tcp"\n    port = "22"\n    source_ips = ["0.0.0.0/0"]\n  }\n}', False),
    ("scaleway default range", 'resource "scaleway_instance_security_group" "f" {\n  inbound_default_policy = "drop"\n  inbound_rule {\n    action = "accept"\n    protocol = "TCP"\n    port = 22\n  }\n}', True),
    ("scaleway range", 'resource "scaleway_instance_security_group" "f" {\n  inbound_default_policy = "drop"\n  inbound_rule {\n    action = "accept"\n    ip_range = "198.51.100.0/24"\n    protocol = "TCP"\n    port = 22\n  }\n}', False),
    ("alicloud open", 'resource "alicloud_security_group_rule" "r" {\n  type = "ingress"\n  ip_protocol = "tcp"\n  port_range = "22/22"\n  cidr_ip = "0.0.0.0/0"\n}', True),
    ("alicloud all ports", 'resource "alicloud_security_group_rule" "r" {\n  type = "ingress"\n  ip_protocol = "all"\n  port_range = "-1/-1"\n  cidr_ip = "0.0.0.0/0"\n}', True),
    ("alicloud drop", 'resource "alicloud_security_group_rule" "r" {\n  type = "ingress"\n  policy = "drop"\n  ip_protocol = "tcp"\n  port_range = "22/22"\n  cidr_ip = "0.0.0.0/0"\n}', False),
    ("alicloud egress", 'resource "alicloud_security_group_rule" "r" {\n  type = "egress"\n  ip_protocol = "tcp"\n  port_range = "22/22"\n  cidr_ip = "0.0.0.0/0"\n}', False),
    ("alicloud type unknown", 'resource "alicloud_security_group_rule" "r" {\n  type = var.t\n  ip_protocol = "tcp"\n  port_range = "22/22"\n  cidr_ip = "0.0.0.0/0"\n}', None),
    ("tencent open", 'resource "tencentcloud_security_group_rule" "r" {\n  type = "ingress"\n  policy = "ACCEPT"\n  ip_protocol = "TCP"\n  port_range = "22"\n  cidr_ip = "0.0.0.0/0"\n}', True),
    ("tencent policy omitted", 'resource "tencentcloud_security_group_rule" "r" {\n  type = "ingress"\n  ip_protocol = "TCP"\n  port_range = "22"\n  cidr_ip = "0.0.0.0/0"\n}', None),
    ("huawei open", 'resource "huaweicloud_networking_secgroup_rule" "r" {\n  direction = "ingress"\n  protocol = "tcp"\n  port_range_min = 22\n  port_range_max = 22\n  remote_ip_prefix = "0.0.0.0/0"\n}', True),
    ("openstack no source", 'resource "openstack_networking_secgroup_rule_v2" "r" {\n  direction = "ingress"\n  protocol = "tcp"\n  port_range_min = 22\n  port_range_max = 22\n}', True),
    ("openstack no source v6", 'resource "openstack_networking_secgroup_rule_v2" "r" {\n  direction = "ingress"\n  ethertype = "IPv6"\n  protocol = "tcp"\n  port_range_min = 22\n  port_range_max = 22\n}', False),
    ("openstack group source", 'resource "openstack_networking_secgroup_rule_v2" "r" {\n  direction = "ingress"\n  protocol = "tcp"\n  port_range_min = 22\n  port_range_max = 22\n  remote_group_id = "g"\n}', False),
    ("openstack computed group", 'resource "openstack_networking_secgroup_rule_v2" "r" {\n  direction = "ingress"\n  protocol = "tcp"\n  port_range_min = 22\n  port_range_max = 22\n  remote_group_id = var.g\n}', None),
    ("linode accept default", 'resource "linode_firewall" "f" {\n  inbound_policy = "ACCEPT"\n}', True),
    ("linode policy omitted", 'resource "linode_firewall" "f" {\n  inbound {\n    action = "DROP"\n    protocol = "TCP"\n  }\n}', None),
    ("linode policy computed", 'resource "linode_firewall" "f" {\n  inbound_policy = var.p\n}', None),
    ("scaleway default accept", 'resource "scaleway_instance_security_group" "f" {\n}', True),
    ("scaleway explicit drop", 'resource "scaleway_instance_security_group" "f" {\n  inbound_default_policy = "drop"\n}', False),
    ("openstack min only", 'resource "openstack_networking_secgroup_rule_v2" "r" {\n  direction = "ingress"\n  protocol = "tcp"\n  port_range_min = 22\n  remote_ip_prefix = "0.0.0.0/0"\n}', True),
    ("openstack computed ports", 'resource "openstack_networking_secgroup_rule_v2" "r" {\n  direction = "ingress"\n  protocol = "tcp"\n  port_range_min = var.p\n  port_range_max = 22\n  remote_ip_prefix = "0.0.0.0/0"\n}', None),
    ("openstack other port", 'resource "openstack_networking_secgroup_rule_v2" "r" {\n  direction = "ingress"\n  protocol = "tcp"\n  port_range_min = 443\n  port_range_max = 443\n  remote_ip_prefix = "0.0.0.0/0"\n}', False),
]


@pytest.mark.parametrize("name,tf,expected", CASES, ids=[c[0] for c in CASES])
def test_provider_firewalls(name, tf, expected):
    assert ssh(tf)[SSH] is expected


def test_omitted_ports_mean_every_port_and_missing_protocol_is_unknown():
    out = ssh('resource "digitalocean_firewall" "f" {\n  inbound_rule {\n    protocol = "tcp"\n    source_addresses = ["0.0.0.0/0"]\n  }\n}')
    assert out[SSH] is True
    out = ssh('resource "openstack_networking_secgroup_rule_v2" "r" {\n  direction = "ingress"\n  remote_ip_prefix = "0.0.0.0/0"\n}')
    assert out[SSH] is None and out[ALL] is None
    out = ssh('resource "linode_firewall" "f" {\n  inbound_policy = "DROP"\n  inbound {\n    action = "ACCEPT"\n    protocol = "TCP"\n    ports = "1-65535"\n    ipv4 = ["0.0.0.0/0"]\n  }\n}')
    assert out[SSH] is True


def test_fw_edge_helpers():
    def res(t, props):
        return Resource("x", "", t, "r", t + ".r", props, Source("f", 1, 1))
    assert ex.network_ingress(res("digitalocean_firewall", {"inbound_rule": Unknown("x")}))[SSH] is None
    assert ex.network_ingress(res("hcloud_firewall", {"rule": [{"direction": "in", "protocol": "tcp", "port": Ref("v"), "source_ips": ["0.0.0.0/0"]}]}))[SSH] is None
    assert ex._gate({"a": Unknown("x")}, ("a", ("x",), False)) is None
    assert ex._gate({}, ("a", ("x",), False)) is True
    assert ex._fw_ports({"port_range_max": 22}, {"minmax": ("port_range_min", "port_range_max")}) == ["22-22"]
