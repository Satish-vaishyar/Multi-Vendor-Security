import json

import pytest

from cloud.ir import Ref, Resource, Source, Unknown
from cloud.parsers.cloudformation import parse_cloudformation
from cloud.parsers.kubernetes import parse_kubernetes
from cloud.parsers.terraform import parse_terraform
from cloud.rules import extractors as ex


def tf(text):
    r = parse_terraform([("main.tf", text)])
    assert r.errors == []
    return r.resources


def net(text, index=0):
    return ex.network_ingress(tf(text)[index])


def res(rtype, props, name="r"):
    return Resource("x", "", rtype, name, f"{rtype}.{name}", props, Source("f", 1, 1))


# ------------------------------------------------------------------ paths, ops, declarative specs
def test_get_path_walks_dicts_lists_and_blocks():
    p = {"a": {"b": [{"c": 1}, {"c": 2}]}, "blk": [{"k": "v"}], "u": Unknown("x"), "r": Ref("x.y"), "empty": []}
    assert ex.get_path(p, "a.b[1].c") == 2 and ex.get_path(p, "a.b[9].c") is ex.MISSING
    assert ex.get_path(p, "blk.k") == "v"                       # a bare key on a block list means the first block
    assert ex.get_path(p, "empty.k") is ex.MISSING and ex.get_path(p, "a.zzz") is ex.MISSING
    assert isinstance(ex.get_path(p, "u.deeper"), Unknown) and isinstance(ex.get_path(p, "r.x"), Ref)
    assert ex.get_path(p, "a.b[0].c.d") is ex.MISSING           # descend through a scalar


def test_operators_are_three_valued():
    A = ex.apply_op
    assert A("eq", "Required", "required") is True and A("ne", "x", "y") is True
    assert A("in", ["a", "b"], "A") is True and A("not_in", ["a"], "b") is True
    assert A("not", None, True) is False and A("not", None, "false") is True and A("not", None, 5.5 if False else "maybe") is None
    assert A("truthy", None, "Enabled") is True and A("truthy", None, "off") is False and A("truthy", None, [1]) is True
    assert A("truthy", None, {}) is False and A("truthy", None, 3) is True and A("truthy", None, "weird") is None
    assert A("no_item_in", ["allUsers"], ["a", "b"]) is True and A("no_item_in", ["allUsers"], "allUsers") is False
    assert A("no_item_in", ["allUsers"], ["a", Unknown("x")]) is None
    assert A("tls_ok", None, "TLS1_2") is True and A("tls_ok", None, "TLS1_0") is False and A("tls_ok", None, "1.3") is True
    assert A("tls_ok", None, "TLS12") is True and A("tls_ok", None, "latest") is None
    assert A("eq", "x", None) is None


def test_eval_spec_paths_defaults_and_all_true():
    props = {"enc": "enabled", "unk": Unknown("x"), "f1": True, "f2": False, "f3": Unknown("y")}
    assert ex.eval_spec({"paths": ["zz", "enc"], "op": "truthy"}, props) is True
    assert ex.eval_spec({"paths": ["zz"], "op": "truthy", "default": False}, props) is False
    assert ex.eval_spec({"paths": ["zz"], "op": "truthy"}, props) is None
    assert ex.eval_spec({"paths": ["unk"], "op": "truthy", "default": True}, props) is None
    assert ex.eval_spec({"paths": ["enc"]}, props) == "enabled"
    assert ex.eval_spec({"all_true": [["f1"], ["f1"]]}, props) is True
    assert ex.eval_spec({"all_true": [["f1"], ["f2"]]}, props) is False
    assert ex.eval_spec({"all_true": [["f1"], ["f3"]]}, props) is None
    assert ex.eval_spec({"all_true": [["f1"], ["nope", "alt"]]}, props) is None
    assert ex.eval_spec({"all_true": [["nope", "f1"]]}, props) is True      # alternatives: first present wins


# ------------------------------------------------------------------ network rules (AWS Terraform)
AWS_SG = 'resource "aws_security_group" "s" {\n  ingress {\n    from_port = %s\n    to_port = %s\n    protocol = "%s"\n    cidr_blocks = %s\n  }\n}\n'


@pytest.mark.parametrize("lo,hi,proto,cidr,expect", [
    (22, 22, "tcp", '["0.0.0.0/0"]', {"NET.SG.PUBLIC_SSH_V4": True, "NET.SG.PUBLIC_SSH_V6": False, "NET.SG.PUBLIC_RDP": False,
                                      "NET.SG.PUBLIC_ALL": False, "NET.SG.PUBLIC_DB": False}),
    (3389, 3389, "tcp", '["0.0.0.0/0"]', {"NET.SG.PUBLIC_RDP": True, "NET.SG.PUBLIC_SSH_V4": False}),
    (5432, 5432, "6", '["0.0.0.0/0"]', {"NET.SG.PUBLIC_DB": True}),
    (0, 65535, "-1", '["0.0.0.0/0"]', {"NET.SG.PUBLIC_ALL": True, "NET.SG.PUBLIC_SSH_V4": True, "NET.SG.PUBLIC_RDP": True}),
    (1000, 4000, "tcp", '["0.0.0.0/0"]', {"NET.SG.PUBLIC_DB": True, "NET.SG.PUBLIC_RDP": True, "NET.SG.PUBLIC_SSH_V4": False}),
    (22, 22, "udp", '["0.0.0.0/0"]', {"NET.SG.PUBLIC_SSH_V4": False}),
    (22, 22, "tcp", '["10.0.0.0/8"]', {"NET.SG.PUBLIC_SSH_V4": False, "NET.SG.PUBLIC_ALL": False}),
    (22, 22, "tcp", '[]', {"NET.SG.PUBLIC_SSH_V4": False}),
    (22, 22, "tcp", 'var.cidr', {"NET.SG.PUBLIC_SSH_V4": None, "NET.SG.PUBLIC_RDP": False}),
    (22, 22, "tcp", '["10.0.0.0/8", var.cidr]', {"NET.SG.PUBLIC_SSH_V4": None}),
])
def test_aws_security_group_matrix(lo, hi, proto, cidr, expect):
    out = net(AWS_SG % (lo, hi, proto, cidr))
    for prop, value in expect.items():
        assert out[prop] is value, prop


def test_aws_security_group_ipv6_unknown_ports_and_dynamic_blocks():
    v6 = net('resource "aws_security_group" "s" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    protocol = "tcp"\n    ipv6_cidr_blocks = ["::/0"]\n  }\n}\n')
    assert v6["NET.SG.PUBLIC_SSH_V6"] is True and v6["NET.SG.PUBLIC_SSH_V4"] is False and v6["NET.SG.PUBLIC_RDP"] is False
    unk = net('resource "aws_security_group" "s" {\n  ingress {\n    from_port = var.p\n    to_port = var.p\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
    assert unk["NET.SG.PUBLIC_SSH_V4"] is None and unk["NET.SG.PUBLIC_ALL"] is False
    assert all(v is None for v in net('resource "aws_security_group" "s" {\n  dynamic "ingress" {\n    for_each = var.r\n    content { from_port = 1 }\n  }\n}\n').values())
    assert net('resource "aws_security_group" "s" { name = "n" }\n')["NET.SG.PUBLIC_SSH_V4"] is False
    noproto = net('resource "aws_security_group" "s" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
    assert noproto["NET.SG.PUBLIC_SSH_V4"] is None
    noport = net('resource "aws_security_group" "s" {\n  ingress {\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
    assert noport["NET.SG.PUBLIC_SSH_V4"] is None and noport["NET.SG.PUBLIC_ALL"] is False   # tcp is not "all protocols"


def test_aws_rule_resources_and_cloudformation():
    ing = 'resource "aws_security_group_rule" "r" {\n  type = "ingress"\n  from_port = 22\n  to_port = 22\n  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
    assert net(ing)["NET.SG.PUBLIC_SSH_V4"] is True
    assert net(ing.replace('"ingress"', '"egress"'))["NET.SG.PUBLIC_SSH_V4"] is False
    assert net(ing.replace('"ingress"', "var.t"))["NET.SG.PUBLIC_SSH_V4"] is None
    v2 = net('resource "aws_vpc_security_group_ingress_rule" "r" {\n  cidr_ipv4 = "0.0.0.0/0"\n  ip_protocol = "tcp"\n  from_port = 3389\n  to_port = 3389\n}\n')
    assert v2["NET.SG.PUBLIC_RDP"] is True
    cfn = parse_cloudformation("a.yaml", """\
Resources:
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - {IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: 0.0.0.0/0}
        - {IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIpv6: '::/0'}
        - junk
  One:
    Type: AWS::EC2::SecurityGroupIngress
    Properties: {IpProtocol: tcp, FromPort: 3389, ToPort: 3389, CidrIp: 0.0.0.0/0}
  Dyn:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress: !Ref Nope
""").resources
    sg, one, dyn = (ex.network_ingress(r) for r in cfn)
    assert sg["NET.SG.PUBLIC_SSH_V4"] is True and sg["NET.SG.PUBLIC_SSH_V6"] is True
    assert one["NET.SG.PUBLIC_RDP"] is True and dyn["NET.SG.PUBLIC_SSH_V4"] is None


# ------------------------------------------------------------------ other providers
def test_gcp_firewall():
    gcp = lambda body: net('resource "google_compute_firewall" "f" {\n%s\n}\n' % body)
    assert gcp('  source_ranges = ["0.0.0.0/0"]\n  allow {\n    protocol = "tcp"\n    ports = ["22"]\n  }')["NET.SG.PUBLIC_SSH_V4"] is True
    assert gcp('  source_ranges = ["0.0.0.0/0"]\n  allow {\n    protocol = "tcp"\n    ports = ["20-30", "443"]\n  }')["NET.SG.PUBLIC_SSH_V4"] is True
    assert gcp('  source_ranges = ["0.0.0.0/0"]\n  allow {\n    protocol = "all"\n  }')["NET.SG.PUBLIC_ALL"] is True
    assert gcp('  direction = "EGRESS"\n  source_ranges = ["0.0.0.0/0"]\n  allow {\n    protocol = "tcp"\n    ports = ["22"]\n  }')["NET.SG.PUBLIC_SSH_V4"] is False
    assert gcp('  direction = var.d\n  allow {\n    protocol = "tcp"\n  }')["NET.SG.PUBLIC_SSH_V4"] is None
    assert gcp('  source_ranges = ["0.0.0.0/0"]\n  dynamic "allow" {\n    for_each = var.a\n    content { protocol = "tcp" }\n  }')["NET.SG.PUBLIC_SSH_V4"] is None
    assert gcp('  source_ranges = ["0.0.0.0/0"]\n  allow {\n    protocol = "tcp"\n    ports = ["abc"]\n  }')["NET.SG.PUBLIC_SSH_V4"] is None
    assert gcp('  source_ranges = ["0.0.0.0/0"]\n  allow {\n    protocol = "tcp"\n    ports = [var.p]\n  }')["NET.SG.PUBLIC_SSH_V4"] is None


def test_azure_nsg_terraform_and_arm():
    rule = lambda extra: net('resource "azurerm_network_security_rule" "r" {\n  direction = "Inbound"\n  access = "Allow"\n  protocol = "Tcp"\n%s\n}\n' % extra)
    assert rule('  source_address_prefix = "*"\n  destination_port_range = "22"')["NET.SG.PUBLIC_SSH_V4"] is True
    assert rule('  source_address_prefixes = ["Internet"]\n  destination_port_ranges = ["3389", "80"]')["NET.SG.PUBLIC_RDP"] is True
    assert rule('  source_address_prefix = "10.0.0.0/8"\n  destination_port_range = "22"')["NET.SG.PUBLIC_SSH_V4"] is False
    assert rule('  source_address_prefix = "*"\n  destination_port_range = "*"')["NET.SG.PUBLIC_ALL"] is False   # Tcp only, not all protocols
    deny = net('resource "azurerm_network_security_rule" "r" {\n  direction = "Inbound"\n  access = "Deny"\n  source_address_prefix = "*"\n  destination_port_range = "22"\n}\n')
    assert deny["NET.SG.PUBLIC_SSH_V4"] is False
    nsg = net('resource "azurerm_network_security_group" "g" {\n  security_rule {\n    direction = "Inbound"\n    access = "Allow"\n    protocol = "*"\n    source_address_prefix = "*"\n    destination_port_range = "*"\n  }\n}\n')
    assert nsg["NET.SG.PUBLIC_ALL"] is True
    assert net('resource "azurerm_network_security_group" "g" {\n  dynamic "security_rule" {\n    for_each = var.r\n    content { name = "x" }\n  }\n}\n')["NET.SG.PUBLIC_SSH_V4"] is None
    arm = res("Microsoft.Network/networkSecurityGroups", {"properties": {"securityRules": [
        {"name": "ssh", "properties": {"direction": "Inbound", "access": "Allow", "protocol": "Tcp", "sourceAddressPrefix": "*",
                                       "destinationPortRange": "22"}}, "junk"]}})
    assert ex.network_ingress(arm)["NET.SG.PUBLIC_SSH_V4"] is True
    assert ex.network_ingress(res("Microsoft.Network/networkSecurityGroups", {"properties": {}}))["NET.SG.PUBLIC_SSH_V4"] is False
    assert ex.network_ingress(res("Microsoft.Network/networkSecurityGroups", {"properties": {"securityRules": Unknown("x")}}))["NET.SG.PUBLIC_SSH_V4"] is None


def test_oci_security_lists_and_nsg_rules():
    sl = lambda body: net('resource "oci_core_security_list" "s" {\n  ingress_security_rules {\n%s\n  }\n}\n' % body)
    assert sl('    protocol = "6"\n    source = "0.0.0.0/0"\n    tcp_options {\n      min = 22\n      max = 22\n    }')["NET.SG.PUBLIC_SSH_V4"] is True
    assert sl('    protocol = "6"\n    source = "0.0.0.0/0"')["NET.SG.PUBLIC_ALL"] is False        # tcp (not all protocols) on all ports
    assert sl('    protocol = "6"\n    source = "0.0.0.0/0"')["NET.SG.PUBLIC_SSH_V4"] is True
    assert sl('    protocol = "17"\n    source = "0.0.0.0/0"')["NET.SG.PUBLIC_SSH_V4"] is False
    assert sl('    protocol = "all"\n    source = "0.0.0.0/0"')["NET.SG.PUBLIC_ALL"] is True
    assert net('resource "oci_core_security_list" "s" {\n  dynamic "ingress_security_rules" {\n    for_each = var.r\n    content { protocol = "6" }\n  }\n}\n')["NET.SG.PUBLIC_SSH_V4"] is None
    nsg = lambda direction: ex.network_ingress(res("oci_core_network_security_group_security_rule", {
        "direction": direction, "protocol": "6", "source": "0.0.0.0/0",
        "tcp_options": [{"destination_port_range": [{"min": 3389, "max": 3389}]}]}))
    assert nsg("INGRESS")["NET.SG.PUBLIC_RDP"] is True and nsg("EGRESS")["NET.SG.PUBLIC_RDP"] is False
    odd = ex.network_ingress(res("oci_core_network_security_group_security_rule", {
        "direction": "INGRESS", "protocol": "6", "source": "0.0.0.0/0", "tcp_options": [{"destination_port_range": [{"min": Unknown("v")}]}]}))
    assert odd["NET.SG.PUBLIC_SSH_V4"] is None
    plain = ex.network_ingress(res("oci_core_network_security_group_security_rule", {
        "direction": "INGRESS", "protocol": "6", "source": "0.0.0.0/0", "tcp_options": ["junk"]}))
    assert plain["NET.SG.PUBLIC_SSH_V4"] is True


# ------------------------------------------------------------------ IAM
ADMIN = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def iam(rtype, key, doc):
    return ex.iam_policies(res(rtype, {key: doc}))


def test_wildcard_admin_variants():
    assert iam("aws_iam_policy", "policy", ADMIN)["IAM.WILDCARD_ADMIN"] is True
    assert iam("aws_iam_policy", "policy", json.dumps(ADMIN))["IAM.WILDCARD_ADMIN"] is True
    narrow = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}, "junk"]}
    assert iam("aws_iam_policy", "policy", narrow)["IAM.WILDCARD_ADMIN"] is False
    assert iam("aws_iam_policy", "policy", {"Statement": {"Effect": "Deny", "Action": "*", "Resource": "*"}})["IAM.WILDCARD_ADMIN"] is False
    assert iam("aws_iam_policy", "policy", {"Statement": [{"Effect": "Allow", "Action": ["*:*"], "Resource": ["*"]}]})["IAM.WILDCARD_ADMIN"] is True
    assert iam("aws_iam_policy", "policy", {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b"}]})["IAM.WILDCARD_ADMIN"] is False
    assert iam("aws_iam_policy", "policy", {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": Unknown("x")}]})["IAM.WILDCARD_ADMIN"] is None
    assert iam("aws_iam_policy", "policy", Unknown("computed"))["IAM.WILDCARD_ADMIN"] is None
    assert iam("aws_iam_policy", "policy", "not json {")["IAM.WILDCARD_ADMIN"] is None
    assert iam("aws_iam_policy", "policy", "[1]")["IAM.WILDCARD_ADMIN"] is None
    assert iam("AWS::IAM::ManagedPolicy", "PolicyDocument", ADMIN)["IAM.WILDCARD_ADMIN"] is True
    assert ex.iam_policies(res("aws_iam_policy", {}))["IAM.WILDCARD_ADMIN"] is None        # declared but absent
    assert ex.iam_policies(res("aws_s3_bucket", {})) == {}


def test_public_principal_and_trust_policies():
    pub = lambda pr, cond=None: {"Statement": [{"Effect": "Allow", "Principal": pr, "Action": "s3:*", "Resource": "*",
                                                **({"Condition": cond} if cond else {})}]}
    assert iam("aws_s3_bucket_policy", "policy", pub("*"))["IAM.PUBLIC_PRINCIPAL"] is True
    assert iam("aws_s3_bucket_policy", "policy", pub({"AWS": "*"}))["IAM.PUBLIC_PRINCIPAL"] is True
    assert iam("aws_s3_bucket_policy", "policy", pub({"AWS": ["*"]}))["IAM.PUBLIC_PRINCIPAL"] is True
    assert iam("aws_s3_bucket_policy", "policy", pub({"AWS": "arn:aws:iam::1:root"}))["IAM.PUBLIC_PRINCIPAL"] is False
    assert iam("aws_s3_bucket_policy", "policy", pub({"Service": "x.amazonaws.com"}))["IAM.PUBLIC_PRINCIPAL"] is False
    assert iam("aws_s3_bucket_policy", "policy", pub("*", {"StringEquals": {"aws:PrincipalOrgID": "o-1"}}))["IAM.PUBLIC_PRINCIPAL"] is None
    assert iam("aws_s3_bucket_policy", "policy", {"Statement": [{"Effect": "Allow", "Action": "s3:*"}]})["IAM.PUBLIC_PRINCIPAL"] is False
    assert iam("aws_s3_bucket_policy", "policy", pub(Unknown("x")))["IAM.PUBLIC_PRINCIPAL"] is None
    assert iam("aws_iam_role", "assume_role_policy", pub("*"))["IAM.TRUST_UNRESTRICTED"] is True
    assert iam("AWS::IAM::Role", "AssumeRolePolicyDocument", pub({"Service": "ec2.amazonaws.com"}))["IAM.TRUST_UNRESTRICTED"] is False
    assert iam("AWS::S3::BucketPolicy", "PolicyDocument", pub("*"))["IAM.PUBLIC_PRINCIPAL"] is True


def test_gcp_iam():
    pub = ex.gcp_iam(res("google_storage_bucket_iam_member", {"member": "allUsers", "role": "roles/storage.objectViewer"}))
    assert pub == {"IAM.PUBLIC_PRINCIPAL": True, "IAM.WILDCARD_ADMIN": False}
    own = ex.gcp_iam(res("google_project_iam_binding", {"members": ["user:a@x.com", "allAuthenticatedUsers"], "role": "roles/owner"}))
    assert own == {"IAM.PUBLIC_PRINCIPAL": True, "IAM.WILDCARD_ADMIN": True}
    safe = ex.gcp_iam(res("google_project_iam_member", {"member": "user:a@x.com", "role": "roles/viewer"}))
    assert safe == {"IAM.PUBLIC_PRINCIPAL": False, "IAM.WILDCARD_ADMIN": False}
    unk = ex.gcp_iam(res("google_project_iam_member", {"member": Unknown("x"), "role": Unknown("y")}))
    assert unk == {"IAM.PUBLIC_PRINCIPAL": None, "IAM.WILDCARD_ADMIN": None}
    assert ex.gcp_iam(res("google_project_iam_member", {})) == {"IAM.PUBLIC_PRINCIPAL": None, "IAM.WILDCARD_ADMIN": None}


def test_gcp_sql_public_exposure():
    sql = lambda ipc: ex.gcp_sql(res("google_sql_database_instance", {"settings": [{"ip_configuration": ipc}]}))["DB.PUBLICLY_ACCESSIBLE"]
    assert sql([{"authorized_networks": [{"value": "0.0.0.0/0"}]}]) is True
    assert sql([{"ipv4_enabled": False}]) is False
    assert sql([{"ipv4_enabled": True, "authorized_networks": [{"value": "10.0.0.0/8"}]}]) is False
    assert sql([{"ipv4_enabled": True}]) is False
    assert sql([{"authorized_networks": [{"value": Unknown("x")}], "ipv4_enabled": True}]) is None
    assert sql([{"authorized_networks": Unknown("dyn")}]) is None
    assert sql([{"authorized_networks": [{"value": "10.0.0.0/8"}]}]) is None                    # ipv4_enabled omitted
    assert sql([{"ipv4_enabled": Unknown("x"), "authorized_networks": []}]) is None
    assert sql(Unknown("x")) is None
    assert ex.gcp_sql(res("google_sql_database_instance", {}))["DB.PUBLICLY_ACCESSIBLE"] is None


# ------------------------------------------------------------------ Kubernetes
def k8s(text):
    r = parse_kubernetes("k.yaml", text)
    assert r.errors == []
    return r.resources


def test_k8s_workload_properties():
    bad = k8s("""\
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: d}
spec:
  hostNetwork: true
  hostPID: true
  containers:
    - name: a
      image: nginx:latest
      securityContext: {privileged: true, runAsUser: 0, allowPrivilegeEscalation: true, capabilities: {add: [ALL]}}
""")[0]
    out = ex.k8s_workload(bad)
    assert out["K8S.CONTAINER.PRIVILEGED"] is True and out["K8S.CONTAINER.RUN_AS_ROOT"] is True
    assert out["K8S.CONTAINER.ALLOW_PRIVILEGE_ESCALATION"] is True and out["K8S.CONTAINER.CAP_ADD_ALL"] is True
    assert out["K8S.POD.HOST_NETWORK"] is True and out["K8S.POD.HOST_PID"] is True and out["K8S.CONTAINER.IMAGE_UNPINNED"] is True
    good = k8s("""\
apiVersion: apps/v1
kind: Deployment
metadata: {name: d, namespace: d}
spec:
  template:
    spec:
      securityContext: {runAsNonRoot: true}
      containers:
        - name: a
          image: registry.example.com:5000/app@sha256:abc
          securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
        - name: b
          image: app:1.2.3
          securityContext: {runAsUser: 1000, allowPrivilegeEscalation: false}
""")[0]
    g = ex.k8s_workload(good)
    assert g["K8S.CONTAINER.PRIVILEGED"] is False and g["K8S.CONTAINER.RUN_AS_ROOT"] is False
    assert g["K8S.CONTAINER.ALLOW_PRIVILEGE_ESCALATION"] is False and g["K8S.CONTAINER.CAP_ADD_ALL"] is False
    assert g["K8S.POD.HOST_NETWORK"] is False and g["K8S.CONTAINER.IMAGE_UNPINNED"] is False
    bare = ex.k8s_workload(k8s("apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: d}\nspec:\n  containers:\n    - name: a\n      image: nginx\n")[0])
    assert bare["K8S.CONTAINER.RUN_AS_ROOT"] is None                       # user not declared: unknown, never a pass
    assert bare["K8S.CONTAINER.ALLOW_PRIVILEGE_ESCALATION"] is True        # the Kubernetes default is "allowed"
    assert bare["K8S.CONTAINER.IMAGE_UNPINNED"] is True
    assert ex.k8s_workload(k8s("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c, namespace: d}\n")[0]) == {}
    nosc = ex.k8s_workload(k8s("apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: d}\nspec:\n  securityContext: oops\n  containers:\n    - name: a\n      image: x:1\n      securityContext: oops\n      capabilities: oops\n")[0])
    assert nosc["K8S.CONTAINER.PRIVILEGED"] is False


def test_k8s_network_policy():
    allow_all = k8s("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: a, namespace: d}\nspec: {podSelector: {}, policyTypes: [Ingress], ingress: [{}]}\n")[0]
    assert ex.k8s_netpol(allow_all) == {"K8S.NETPOL.ALLOW_ALL": True}
    scoped = k8s("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: a, namespace: d}\nspec: {podSelector: {matchLabels: {a: b}}, ingress: [{}]}\n")[0]
    assert ex.k8s_netpol(scoped) == {"K8S.NETPOL.ALLOW_ALL": False}
    deny = k8s("apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: a, namespace: d}\nspec: {podSelector: {}, policyTypes: [Ingress]}\n")[0]
    assert ex.k8s_netpol(deny) == {"K8S.NETPOL.ALLOW_ALL": False}
    broken = res("NetworkPolicy", {"spec": "oops"})
    assert ex.k8s_netpol(broken) == {"K8S.NETPOL.ALLOW_ALL": False}


def test_remaining_edge_cases():
    weird = net('resource "aws_security_group" "s" {\n  ingress {\n    from_port = "abc"\n    to_port = "abc"\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
    assert weird["NET.SG.PUBLIC_SSH_V4"] is None                          # a non-numeric port is unknown, not a pass
    oci = ex.network_ingress(res("oci_core_network_security_group_security_rule", {
        "direction": "INGRESS", "protocol": "6", "source": "0.0.0.0/0", "tcp_options": [{"other": 1}]}))
    assert oci["NET.SG.PUBLIC_SSH_V4"] is True                            # options without a port range: all TCP ports
    deny = {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*"}]}
    assert iam("aws_s3_bucket_policy", "policy", deny)["IAM.PUBLIC_PRINCIPAL"] is False


# ---------------------------------------------------------------- hardening from the automated security review
@pytest.mark.parametrize("cidr,v4,v6,any_", [
    ("0.0.0.0/0", True, False, True), ("0.0.0.0/1", True, False, True), ("128.0.0.0/2", True, False, True),
    ("::/0", False, True, True), ("8000::/3", False, True, True),
    ("10.0.0.0/8", False, False, False), ("0.0.0.0/8", False, False, False), ("fc00::/7", False, False, False),
    ("203.0.113.0/24", False, False, False), ("8.8.8.8/32", False, False, False), ("2001:db8::/32", False, False, False),
    ("sg-0123456789", False, False, False), ("pl-1234", False, False, False), ("VirtualNetwork", False, False, False),
    ("AzureCloud", None, None, None), ("not-a-network", None, None, None), ("", None, None, None),
])
def test_sources_are_parsed_as_networks_not_matched_as_text(cidr, v4, v6, any_):
    assert ex._public(cidr, "v4") is v4 and ex._public(cidr, "v6") is v6 and ex._public(cidr, "any") is any_


def test_text_wildcards_and_unknown_sources():
    for token in ("*", "Any", "internet"):
        assert ex._public(token, "v4") is True and ex._public(token, "v6") is True
    assert ex._public(Unknown("x"), "v4") is None and ex._public(Ref("a.b"), "any") is None


def test_split_public_ranges_and_unparseable_sources_in_a_real_rule():
    half = net(AWS_SG % (22, 22, "tcp", '["0.0.0.0/1"]'))
    assert half["NET.SG.PUBLIC_SSH_V4"] is True                              # a /1 is half the Internet, not a narrow allow-list
    odd = net(AWS_SG % (22, 22, "tcp", '["AzureCloud"]'))
    assert odd["NET.SG.PUBLIC_SSH_V4"] is None                               # cannot be understood: UNKNOWN, never "not public"
    ref = net(AWS_SG % (22, 22, "tcp", '["sg-0123"]'))
    assert ref["NET.SG.PUBLIC_SSH_V4"] is False


def stmt(**kw):
    return {"Statement": [{"Effect": "Allow", **kw}]}


def test_not_action_not_resource_and_malformed_statements_are_never_a_pass():
    admin = lambda doc: iam("aws_iam_policy", "policy", doc)["IAM.WILDCARD_ADMIN"]
    assert admin(stmt(NotAction="iam:*", Resource="*")) is None              # "everything except X"
    assert admin(stmt(Action="*", NotResource="arn:aws:s3:::b")) is None
    assert admin(stmt(Resource="*")) is None and admin(stmt(Action="*")) is None   # missing Action / Resource: malformed
    assert admin({"Statement": [{"Action": "*", "Resource": "*"}]}) is None         # missing Effect
    assert admin({"Statement": [{"Effect": Unknown("x"), "Action": "*", "Resource": "*"}]}) is None
    assert admin({"Statement": [{"Effect": " allow ", "Action": "*", "Resource": "*"}]}) is True   # normalised, not case-sensitive
    assert admin({"Statement": [{"Effect": "Deny", "NotAction": "*", "Resource": "*"}]}) is False


def test_not_principal_and_every_principal_type_are_checked():
    pub = lambda doc: iam("aws_s3_bucket_policy", "policy", doc)["IAM.PUBLIC_PRINCIPAL"]
    assert pub(stmt(NotPrincipal={"AWS": "arn:aws:iam::1:root"}, Action="s3:*", Resource="*")) is True
    assert pub(stmt(NotPrincipal={"AWS": "arn:x"}, Action="s3:*", Resource="*", Condition={"Bool": {"x": "y"}})) is None
    assert pub(stmt(Principal={"Federated": "*"}, Action="s3:*", Resource="*")) is True
    assert pub(stmt(Principal={"CanonicalUser": ["*"]}, Action="s3:*", Resource="*")) is True
    assert pub(stmt(Principal={"AWS": ["arn:aws:iam::1:root", "*"]}, Action="s3:*", Resource="*")) is True
    assert pub(stmt(Principal={"Service": "x.amazonaws.com", "AWS": Unknown("v")}, Action="s3:*", Resource="*")) is None
    assert pub({"Statement": [{"Principal": "*", "Action": "s3:*"}]}) is None            # missing Effect
    assert pub({"Statement": [{"Effect": Ref("a.b"), "Principal": "*"}]}) is None


@pytest.mark.parametrize("cidr,expect", [
    ("0.0.0.0", True), ("::", True), ("0.0.0.0/0", True), ("::/0", True),
    ("64.0.0.0/10", None), ("32.0.0.0/9", None), ("2000::/12", None), ("2400::/16", None),
    ("::ffff:0:0/96", None), ("64:ff9b::/96", None), ("2002::/16", None), ("::/96", None),
    ("172.16.0.0/12", False), ("192.168.0.0/16", False), ("100.64.0.0/10", False), ("169.254.0.0/16", False),
    ("127.0.0.0/8", False), ("0.0.0.0/8", False), ("fe80::/10", False), ("::1/128", False), ("fd00::/8", False),
    ("203.0.113.0/24", False), ("192.0.2.1/32", False), ("2a00:1450::/32", False),
])
def test_cidr_classification_is_explicit_and_independent_of_python_is_private(cidr, expect):
    assert ex._public(cidr, "any") is expect
