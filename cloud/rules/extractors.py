"""Property extractors: turn provider-specific resources into canonical cloud properties (RTM S12; CM-070..075).

Every property is three-valued: True / False / None, where None means UNKNOWN (value omitted, computed, dynamic or
undeterminable offline). Extractors never turn an unknown into a pass: if any contributing value is unknown and no
other value already settles the answer, the result is None.

Two mechanisms:
  * declarative specs in the mapping YAML (`properties:`) for plain attribute paths, evaluated by `eval_spec`
  * named extractors (`extractors:`) for logic over lists/documents: network rules, IAM policies, Kubernetes workloads
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from cloud.ir import Ref, Resource, Unknown, as_list
from cloud.parsers.kubernetes import containers, pod_spec

MISSING = object()
ALL = "ALL"                                   # sentinel: every port
OPS = ("eq", "ne", "in", "not_in", "not", "truthy", "no_item_in", "tls_ok")


# ------------------------------------------------------------------ attribute paths and declarative specs
def _step(cur: Any, tok: str) -> Any:
    if isinstance(cur, (Unknown, Ref)):
        return cur
    if isinstance(cur, list):
        if tok.isdigit():
            return cur[int(tok)] if int(tok) < len(cur) else MISSING
        cur = cur[0] if cur else MISSING          # HCL blocks are lists; a bare key means "the (first) block"
        if cur is MISSING:
            return MISSING
    return cur.get(tok, MISSING) if isinstance(cur, dict) else MISSING


def get_path(props: Any, path: str) -> Any:
    cur = props
    for tok in re.findall(r"[^.\[\]]+", path):
        cur = _step(cur, tok)
        if cur is MISSING:
            return MISSING
    return cur


def _known(v: Any) -> Any:
    return None if isinstance(v, (Unknown, Ref)) else v


def _truthy(v: Any) -> Optional[bool]:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        low = v.strip().lower()
        return True if low in ("true", "enabled", "yes", "on") else False if low in ("false", "disabled", "no", "off") else None
    if isinstance(v, (list, dict)):
        return bool(v)
    return None if v is None else bool(v)


def _norm(v: Any) -> Any:
    return v.strip().lower() if isinstance(v, str) else v


def _tls_ok(v: Any) -> Optional[bool]:
    m = re.search(r"(\d)[._]?(\d)?", str(v))
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2) or 0)) >= (1, 2)


def apply_op(op: str, arg: Any, value: Any) -> Optional[bool]:
    if value is None:
        return None
    if op == "eq":
        return _norm(value) == _norm(arg)
    if op == "ne":
        return _norm(value) != _norm(arg)
    if op == "in":
        return _norm(value) in [_norm(a) for a in arg]
    if op == "not_in":
        return _norm(value) not in [_norm(a) for a in arg]
    if op == "not":
        t = _truthy(value)
        return None if t is None else not t
    if op == "truthy":
        return _truthy(value)
    if op == "no_item_in":
        items = value if isinstance(value, list) else [value]
        if any(_known(i) is None for i in items):
            return None
        return not any(i in arg for i in items)
    return _tls_ok(value)                       # tls_ok


def eval_spec(spec: Dict[str, Any], props: Dict[str, Any]) -> Optional[bool]:
    if "all_true" in spec:
        states: List[Optional[bool]] = []
        for alternatives in spec["all_true"]:
            val: Any = MISSING
            for path in alternatives:
                val = get_path(props, path)
                if val is not MISSING:
                    break
            states.append(None if val is MISSING else _truthy(_known(val)))
        if any(s is False for s in states):
            return False
        return None if any(s is None for s in states) else True
    for path in spec["paths"]:
        val = get_path(props, path)
        if val is not MISSING:
            break
    else:
        return spec.get("default")
    val = _known(val)
    return apply_op(spec["op"], spec.get("arg"), val) if spec.get("op") else val


# ------------------------------------------------------------------ network exposure
@dataclass
class Rule:
    sources: List[Any]
    proto: Any            # str | Unknown | MISSING
    lo: Any               # int | ALL | Unknown
    hi: Any


_ALL_PROTO = {"-1", "all", "*", "any", ""}
_TCP = {"tcp", "6"}
_DB_PORTS = (1433, 1521, 3306, 5432, 5984, 6379, 9042, 9200, 11211, 27017)
TARGETS: Dict[str, Any] = {
    "NET.SG.PUBLIC_SSH_V4": ("v4", (22,)), "NET.SG.PUBLIC_SSH_V6": ("v6", (22,)), "NET.SG.PUBLIC_RDP": ("any", (3389,)),
    "NET.SG.PUBLIC_DB": ("any", _DB_PORTS), "NET.SG.PUBLIC_ALL": ("any", None)}


def _items(v: Any) -> List[Any]:
    if v is MISSING or v is None:
        return []
    return list(v) if isinstance(v, list) else [v]


def _all(states: List[Optional[bool]]) -> Optional[bool]:
    if any(s is False for s in states):
        return False
    return None if any(s is None for s in states) else True


def _any(states: List[Optional[bool]]) -> Optional[bool]:
    if any(s is True for s in states):
        return True
    return None if any(s is None for s in states) else False


_SAFE_TAGS = {"virtualnetwork", "azureloadbalancer", "gatewaymanager", "azurebastion"}   # non-routable Azure service tags
# Explicit private / non-global ranges (not delegated to ipaddress.is_private, whose answers changed between Python versions).
_PRIVATE = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
    "fc00::/7", "fe80::/10", "::1/128")]
# IPv6 transition / mapped ranges can embed IPv4 space: their reach depends on the translator, so they are UNKNOWN.
_TRANSITION = [ipaddress.ip_network(n) for n in ("::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "::/96")]
_BROAD_PUBLIC = {4: 8, 6: 8}            # prefix <= this: "the Internet" (or a large share of it)
_AMBIGUOUS = {4: 15, 6: 16}             # prefix <= this (and above _BROAD_PUBLIC): a very large range, needs a human


def _public(src: Any, kind: str) -> Optional[bool]:
    """Is this source "the Internet" for the given address family? Parsed as a network, never matched as text only:
    broad ranges are public (/0 .. /8), very large ones are UNKNOWN, narrow public ranges are allow-lists, private and
    non-routable ranges are not public, and anything that cannot be understood is UNKNOWN (never "not public")."""
    if isinstance(src, (Unknown, Ref)):
        return None
    s = str(src).strip().lower()
    if s in ("*", "any", "internet", "0.0.0.0", "::"):
        return True
    if s in _SAFE_TAGS or s.startswith(("sg-", "pl-", "sg_")):
        return False
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None
    family = "v6" if net.version == 6 else "v4"
    if kind != "any" and kind != family:
        return False
    if net.prefixlen == 0:
        return True
    if any(net.version == t.version and net.subnet_of(t) for t in _PRIVATE):
        return False
    if net.version == 6 and any(net.overlaps(t) for t in _TRANSITION):
        return None
    if net.prefixlen <= _BROAD_PUBLIC[net.version]:
        return True
    if net.prefixlen <= _AMBIGUOUS[net.version]:
        return None
    return False


def _proto_state(proto: Any, want_all: bool) -> Optional[bool]:
    if proto is MISSING or isinstance(proto, (Unknown, Ref)):
        return None
    p = str(proto).strip().lower()
    if want_all:
        return p in _ALL_PROTO
    return p in _TCP or p in _ALL_PROTO


def _covers(rule: Rule, port: Optional[int], proto_is_all: Optional[bool]) -> Optional[bool]:
    if port is None:                              # looking for "all ports"
        return True if rule.lo == ALL else None if isinstance(rule.lo, Unknown) or isinstance(rule.hi, Unknown) else False
    if proto_is_all or rule.lo == ALL:
        return True
    if isinstance(rule.lo, (Unknown, Ref)) or isinstance(rule.hi, (Unknown, Ref)):
        return None
    try:
        return int(rule.lo) <= port <= int(rule.hi)
    except (TypeError, ValueError):
        return None


def _rule_state(rule: Rule, kind: str, ports: Optional[tuple]) -> Optional[bool]:
    src = _any([_public(s, kind) for s in rule.sources]) if rule.sources else False
    if ports is None:
        proto = _proto_state(rule.proto, want_all=True)
        return _all([src, proto, _covers(rule, None, None)])
    proto = _proto_state(rule.proto, want_all=False)
    is_all = _proto_state(rule.proto, want_all=True)
    return _all([src, proto, _any([_covers(rule, p, is_all) for p in ports])])


def _port_rules(sources: List[Any], proto: Any, port_specs: List[Any]) -> List[Rule]:
    out: List[Rule] = []
    for spec in port_specs or [MISSING]:
        if spec is MISSING or str(spec).strip().lower() in ("*", "all", "0-65535"):
            out.append(Rule(sources, proto, ALL, ALL))
        elif isinstance(spec, (Unknown, Ref)):
            out.append(Rule(sources, proto, spec, spec))
        else:
            m = re.fullmatch(r"\s*(\d+)\s*(?:-\s*(\d+))?\s*", str(spec))
            out.append(Rule(sources, proto, int(m.group(1)), int(m.group(2) or m.group(1))) if m
                       else Rule(sources, proto, Unknown("unparseable port", str(spec)), Unknown("unparseable port", str(spec))))
    return out


def _aws_rule(sources: List[Any], proto: Any, lo: Any, hi: Any) -> Rule:
    """AWS: protocol -1 / all means every port, whatever the (zeroed) port fields say."""
    if not isinstance(proto, (Unknown, Ref)) and proto is not MISSING and str(proto).strip().lower() in ("-1", "all"):
        return Rule(sources, proto, ALL, ALL)
    return Rule(sources, proto, lo, hi)


def _aws_sg(res: Resource) -> Optional[List[Rule]]:
    p = res.properties
    t = res.resource_type
    if t == "aws_security_group":
        ing = p.get("ingress", [])
        if isinstance(ing, Unknown):
            return None
        rules = []
        for r in as_list(ing):
            if isinstance(r, dict):
                rules.append(_aws_rule(_items(r.get("cidr_blocks")) + _items(r.get("ipv6_cidr_blocks")), r.get("protocol", MISSING),
                                       r.get("from_port", Unknown("no port")), r.get("to_port", Unknown("no port"))))
        return rules
    if t == "aws_security_group_rule":
        kind = p.get("type")
        if isinstance(kind, Unknown):
            return None
        return [_aws_rule(_items(p.get("cidr_blocks")) + _items(p.get("ipv6_cidr_blocks")), p.get("protocol", MISSING),
                          p.get("from_port", Unknown("no port")), p.get("to_port", Unknown("no port")))] if kind == "ingress" else []
    if t == "aws_vpc_security_group_ingress_rule":
        return [_aws_rule(_items(p.get("cidr_ipv4")) + _items(p.get("cidr_ipv6")), p.get("ip_protocol", MISSING),
                          p.get("from_port", Unknown("no port")), p.get("to_port", Unknown("no port")))]
    if t == "AWS::EC2::SecurityGroup":
        ing = p.get("SecurityGroupIngress", [])
        if isinstance(ing, Unknown):
            return None
        return [_aws_rule(_items(r.get("CidrIp", MISSING)) + _items(r.get("CidrIpv6", MISSING)), r.get("IpProtocol", MISSING),
                          r.get("FromPort", Unknown("no port")), r.get("ToPort", Unknown("no port")))
                for r in as_list(ing) if isinstance(r, dict)]
    return [_aws_rule(_items(p.get("CidrIp", MISSING)) + _items(p.get("CidrIpv6", MISSING)), p.get("IpProtocol", MISSING),
                      p.get("FromPort", Unknown("no port")), p.get("ToPort", Unknown("no port")))]   # AWS::EC2::SecurityGroupIngress


def _gcp_firewall(res: Resource) -> Optional[List[Rule]]:
    p = res.properties
    direction = p.get("direction", "INGRESS")
    if isinstance(direction, Unknown):
        return None
    if str(direction).upper() != "INGRESS":
        return []
    allow = p.get("allow", [])
    if isinstance(allow, Unknown):
        return None
    sources = _items(p.get("source_ranges", MISSING))
    rules: List[Rule] = []
    for block in as_list(allow):
        if isinstance(block, dict):
            ports = block.get("ports", MISSING)
            rules.extend(_port_rules(sources, block.get("protocol", MISSING), [] if ports is MISSING else _items(ports)))
    return rules


def _g(d: Dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in d:
            return d[k]
    return MISSING


def _azure_rule(d: Dict[str, Any]) -> List[Rule]:
    if str(_g(d, "access", "Access")).lower() != "allow" or str(_g(d, "direction", "Direction")).lower() != "inbound":
        return []
    sources = _items(_g(d, "source_address_prefix", "sourceAddressPrefix")) + _items(
        _g(d, "source_address_prefixes", "sourceAddressPrefixes"))
    ports = _items(_g(d, "destination_port_range", "destinationPortRange")) + _items(
        _g(d, "destination_port_ranges", "destinationPortRanges"))
    return _port_rules(sources, _g(d, "protocol", "Protocol"), ports)


def _azure_nsg(res: Resource) -> Optional[List[Rule]]:
    p = res.properties
    if res.resource_type == "azurerm_network_security_rule":
        return _azure_rule(p)
    if res.resource_type == "azurerm_network_security_group":
        rules = p.get("security_rule", [])
        return None if isinstance(rules, Unknown) else [r for d in as_list(rules) if isinstance(d, dict) for r in _azure_rule(d)]
    rules = get_path(p, "properties.securityRules")
    if isinstance(rules, Unknown):
        return None
    return [r for d in as_list(rules if rules is not MISSING else []) if isinstance(d, dict)
            for r in _azure_rule(d.get("properties", d) if isinstance(d.get("properties", d), dict) else d)]


def _oci_ports(opts: Any) -> List[Any]:
    d = as_list(opts)[0] if as_list(opts) else None
    if not isinstance(d, dict):
        return []
    rng = d.get("destination_port_range")
    d = as_list(rng)[0] if rng is not None and as_list(rng) else d
    if isinstance(d, dict) and "min" in d:
        return [f"{d['min']}-{d.get('max', d['min'])}" if not isinstance(d["min"], (Unknown, Ref)) else d["min"]]
    return []


def _oci(res: Resource) -> Optional[List[Rule]]:
    p = res.properties
    if res.resource_type == "oci_core_security_list":
        ing = p.get("ingress_security_rules", [])
        if isinstance(ing, Unknown):
            return None
        return [r for d in as_list(ing) if isinstance(d, dict)
                for r in _port_rules(_items(d.get("source", MISSING)), d.get("protocol", MISSING), _oci_ports(d.get("tcp_options")))]
    if str(p.get("direction", "")).upper() != "INGRESS":
        return []
    return _port_rules(_items(p.get("source", MISSING)), p.get("protocol", MISSING), _oci_ports(p.get("tcp_options")))


_RULE_SOURCES: Dict[str, Callable[[Resource], Optional[List[Rule]]]] = {
    **{t: _aws_sg for t in ("aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule",
                            "AWS::EC2::SecurityGroup", "AWS::EC2::SecurityGroupIngress")},
    "google_compute_firewall": _gcp_firewall,
    **{t: _azure_nsg for t in ("azurerm_network_security_rule", "azurerm_network_security_group",
                               "Microsoft.Network/networkSecurityGroups")},
    **{t: _oci for t in ("oci_core_security_list", "oci_core_network_security_group_security_rule")},
}


def network_ingress(res: Resource) -> Dict[str, Optional[bool]]:
    rules = _RULE_SOURCES[res.resource_type](res)
    out: Dict[str, Optional[bool]] = {}
    for prop, (kind, ports) in TARGETS.items():
        out[prop] = None if rules is None else _any([_rule_state(r, kind, ports) for r in rules])
    return out


# ------------------------------------------------------------------ IAM
_IDENTITY = {"aws_iam_policy": "policy", "aws_iam_role_policy": "policy", "aws_iam_user_policy": "policy",
             "aws_iam_group_policy": "policy", "AWS::IAM::Policy": "PolicyDocument", "AWS::IAM::ManagedPolicy": "PolicyDocument"}
_RESOURCE_POLICY = {"aws_s3_bucket_policy": "policy", "aws_sqs_queue_policy": "policy", "aws_sns_topic_policy": "policy",
                    "aws_kms_key": "policy", "AWS::S3::BucketPolicy": "PolicyDocument", "AWS::SQS::QueuePolicy": "PolicyDocument",
                    "AWS::SNS::TopicPolicy": "PolicyDocument", "AWS::KMS::Key": "KeyPolicy"}
_TRUST = {"aws_iam_role": "assume_role_policy", "AWS::IAM::Role": "AssumeRolePolicyDocument"}


def _doc(value: Any) -> Optional[Dict[str, Any]]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            d = json.loads(value)
        except ValueError:
            return None
        return d if isinstance(d, dict) else None
    return None


def _statements(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [s for s in as_list(doc.get("Statement")) if isinstance(s, dict)]


def _star(v: Any, *needles: str) -> Optional[bool]:
    items = as_list(v)
    if any(isinstance(i, (Unknown, Ref)) for i in items):
        return None
    return any(i in needles for i in items)


def _effect_allows(s: Dict[str, Any]) -> Optional[bool]:
    e = s.get("Effect")
    if isinstance(e, (Unknown, Ref)) or e is None:
        return None
    return str(e).strip().lower() == "allow"


def _wildcard_admin(doc: Dict[str, Any]) -> Optional[bool]:
    """Allow + (Action "*" and Resource "*"). NotAction / NotResource on an Allow grant "everything except X", and a
    missing Action or Resource is malformed: both are UNKNOWN, never a pass."""
    states: List[Optional[bool]] = []
    for s in _statements(doc):
        allows = _effect_allows(s)
        if allows is False:
            continue
        if allows is None:
            states.append(None)
            continue
        if "NotAction" in s or "NotResource" in s or "Action" not in s or "Resource" not in s:
            states.append(None)
            continue
        states.append(_all([_star(s.get("Action"), "*", "*:*"), _star(s.get("Resource"), "*")]))
    return _any(states)


def _principal_values(pr: Any) -> List[Any]:
    """Every principal value regardless of type (AWS, Federated, CanonicalUser, Service) or a bare string."""
    if isinstance(pr, dict):
        return [v for vals in pr.values() for v in as_list(vals)]
    return as_list(pr)


def _public_principal(doc: Dict[str, Any]) -> Optional[bool]:
    states: List[Optional[bool]] = []
    for s in _statements(doc):
        allows = _effect_allows(s)
        if allows is False:
            continue
        if allows is None:
            states.append(None)
            continue
        if "NotPrincipal" in s:
            states.append(None if s.get("Condition") else True)       # "everyone except ..." is public to everyone else
            continue
        values = _principal_values(s.get("Principal"))
        if any(isinstance(v, (Unknown, Ref)) for v in values):
            states.append(None)
            continue
        star = "*" in values
        states.append(None if (star and s.get("Condition")) else star)  # a Condition may restrict the principal
    return _any(states)


def iam_policies(res: Resource) -> Dict[str, Optional[bool]]:
    out: Dict[str, Optional[bool]] = {}
    t, p = res.resource_type, res.properties
    for table, prop, fn in ((_IDENTITY, "IAM.WILDCARD_ADMIN", _wildcard_admin), (_RESOURCE_POLICY, "IAM.PUBLIC_PRINCIPAL", _public_principal),
                            (_TRUST, "IAM.TRUST_UNRESTRICTED", _public_principal)):
        if t in table:
            val = p.get(table[t], MISSING)
            doc = None if val is MISSING else _doc(val)
            out[prop] = None if doc is None else fn(doc)
    return out


def gcp_iam(res: Resource) -> Dict[str, Optional[bool]]:
    p = res.properties
    members = _items(p.get("member", MISSING)) + _items(p.get("members", MISSING))
    role = p.get("role", MISSING)
    pub: Optional[bool] = _any([None if isinstance(m, (Unknown, Ref)) else m in ("allUsers", "allAuthenticatedUsers") for m in members]) if members else None
    admin: Optional[bool] = None if role is MISSING or isinstance(role, (Unknown, Ref)) else role in ("roles/owner", "roles/editor")
    return {"IAM.PUBLIC_PRINCIPAL": pub, "IAM.WILDCARD_ADMIN": admin}


def gcp_sql(res: Resource) -> Dict[str, Optional[bool]]:
    ipc = get_path(res.properties, "settings.ip_configuration")
    if ipc is MISSING or isinstance(ipc, (Unknown, Ref)):
        return {"DB.PUBLICLY_ACCESSIBLE": None}
    nets = get_path(ipc, "authorized_networks")
    if isinstance(nets, (Unknown, Ref)):
        return {"DB.PUBLICLY_ACCESSIBLE": None}
    values = [n.get("value") for n in as_list(nets if nets is not MISSING else []) if isinstance(n, dict)]
    states = [None if isinstance(v, (Unknown, Ref)) else v == "0.0.0.0/0" for v in values]
    if _any(states) is True:
        return {"DB.PUBLICLY_ACCESSIBLE": True}
    enabled = get_path(ipc, "ipv4_enabled")
    if enabled is False:
        return {"DB.PUBLICLY_ACCESSIBLE": False}
    return {"DB.PUBLICLY_ACCESSIBLE": None if _any(states) is None or enabled is MISSING or isinstance(enabled, (Unknown, Ref)) else False}


# ------------------------------------------------------------------ Kubernetes
def _flag(values: List[Optional[bool]]) -> Optional[bool]:
    return _any(values)


def k8s_workload(res: Resource) -> Dict[str, Optional[bool]]:
    spec = pod_spec(res)
    if spec is None:
        return {}
    pod_sc = spec.get("securityContext") if isinstance(spec.get("securityContext"), dict) else {}
    cs = containers(spec)
    priv, root, esc, cap_all, unpinned = [], [], [], [], []
    for c in cs:
        sc = c.get("securityContext") if isinstance(c.get("securityContext"), dict) else {}
        priv.append(sc.get("privileged") is True)
        uid = sc.get("runAsUser", pod_sc.get("runAsUser"))
        nonroot = sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot"))
        root.append(True if uid == 0 else False if (nonroot is True or (isinstance(uid, int) and uid > 0)) else None)
        esc.append(sc.get("allowPrivilegeEscalation") is not False)     # Kubernetes default is true
        caps = (sc.get("capabilities") or {}).get("add") if isinstance(sc.get("capabilities"), dict) else None
        cap_all.append("ALL" in (caps or []))
        image = str(c.get("image", ""))
        unpinned.append("@sha256:" not in image and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")))
    return {"K8S.POD.HOST_NETWORK": spec.get("hostNetwork") is True, "K8S.POD.HOST_PID": spec.get("hostPID") is True,
            "K8S.CONTAINER.PRIVILEGED": _flag(priv), "K8S.CONTAINER.RUN_AS_ROOT": _flag(root),
            "K8S.CONTAINER.ALLOW_PRIVILEGE_ESCALATION": _flag(esc), "K8S.CONTAINER.CAP_ADD_ALL": _flag(cap_all),
            "K8S.CONTAINER.IMAGE_UNPINNED": _flag(unpinned)}


def k8s_netpol(res: Resource) -> Dict[str, Optional[bool]]:
    spec = res.properties.get("spec") if isinstance(res.properties.get("spec"), dict) else {}
    selects_all = spec.get("podSelector") in ({}, None)
    open_rule = any(r == {} for key in ("ingress", "egress") for r in (spec.get(key) or []))
    return {"K8S.NETPOL.ALLOW_ALL": bool(selects_all and open_rule)}


REGISTRY: Dict[str, Callable[[Resource], Dict[str, Optional[bool]]]] = {
    "network_ingress": network_ingress, "iam_policies": iam_policies, "gcp_iam": gcp_iam, "gcp_sql": gcp_sql,
    "k8s_workload": k8s_workload, "k8s_netpol": k8s_netpol}
