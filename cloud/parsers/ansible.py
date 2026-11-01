"""Ansible playbook parser (RTM S29; CM-056): cloud security-group tasks only.

A playbook is a program; it is never run and no module is imported. Only the declarative arguments of `ec2_group` /
`amazon.aws.ec2_group` tasks are read and mapped to the equivalent Terraform-shaped IR resource so the existing AWS rules apply.
Jinja expressions (`{{ ... }}`) become `Unknown`. Every other task is ignored.
"""
from __future__ import annotations

from typing import Any, Dict, Iterator, List

from cloud import yamlutil
from cloud.ir import Resource, Source, Unknown
from cloud.parsers.terraform import ParseResult

_PARSER = "cloud.parsers.ansible 1"
_EC2_GROUP = ("ec2_group", "amazon.aws.ec2_group", "community.aws.ec2_group", "ec2_security_group")
MAX_TASKS = 5000
MAX_DEPTH = 10


def _lit(v: Any) -> Any:
    return Unknown("Jinja expression is not evaluated offline") if isinstance(v, str) and ("{{" in v or "{%" in v) else v


def _list(v: Any) -> List[Any]:
    return [] if v is None else [_lit(x) for x in v] if isinstance(v, list) else [_lit(v)]


def _tasks(items: Any, depth: int = 0) -> Iterator[Dict[str, Any]]:
    if depth > MAX_DEPTH or not isinstance(items, list):
        return
    for t in items:
        if isinstance(t, dict):
            yield t
            for key in ("block", "rescue", "always"):
                yield from _tasks(t.get(key), depth + 1)


def _ingress(rules: Any) -> Any:
    """The Terraform-shaped ingress list, or Unknown when the rules cannot be read in full (a Jinja string, a non-list, or any
    item that is not a mapping): never a shorter list, which would read as a pass."""
    if rules is None:
        return []
    if not isinstance(rules, list) or not all(isinstance(r, dict) for r in rules):
        return Unknown("rules are templated or not a list of mappings")
    out: List[Dict[str, Any]] = []
    for r in rules:
        ports = _list(r.get("ports")) or [None]
        for p in ports:
            if p is None:
                lo, hi = r.get("from_port", Unknown("no port")), r.get("to_port", Unknown("no port"))
            elif isinstance(p, str) and "-" in p:
                lo, hi = (x.strip() for x in p.split("-", 1))
            else:
                lo = hi = p
            out.append({"protocol": _lit(r.get("proto", "tcp")), "from_port": _lit(lo), "to_port": _lit(hi),
                        "cidr_blocks": _list(r.get("cidr_ip")), "ipv6_cidr_blocks": _list(r.get("cidr_ipv6"))})
    return out


def parse_ansible(path: str, text: str) -> ParseResult:
    result = ParseResult()
    try:
        docs = yamlutil.load_all(text)
    except yamlutil.YamlError as e:
        result.errors.append({"file": path, "error": f"invalid YAML: {e}"[:200]})
        return result
    seen = 0
    for doc in docs:
        for play in doc if isinstance(doc, list) else []:
            if not isinstance(play, dict):
                continue
            for section in ("pre_tasks", "tasks", "post_tasks"):
                for task in _tasks(play.get(section)):
                    seen += 1
                    if seen > MAX_TASKS:
                        result.truncated = True
                        return result
                    module = next((m for m in _EC2_GROUP if isinstance(task.get(m), dict)), None)
                    if module is None or task[module].get("state") == "absent":
                        continue
                    args = task[module]
                    name = str(_lit(args.get("name", task.get("name", "(unnamed)"))))[:200]
                    line = yamlutil.line_of(task)
                    result.resources.append(Resource(
                        provider="aws", service="ansible", resource_type="aws_security_group", logical_name=name,
                        address=f"ansible/{name}#{line}", properties={"name": name, "ingress": _ingress(args.get("rules"))},
                        source=Source(path, line, line, "ansible", _PARSER),
                        notes=["mapped from the Ansible ec2_group module; rules_egress is not assessed"]).finalize())
    return result
