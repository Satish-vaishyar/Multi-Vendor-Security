"""Pulumi stack export parser (RTM S29; CM-057): `pulumi stack export` JSON only.

The Pulumi *program* is code and is never executed; the exported state holds the resolved inputs. Only a small, explicit table of
resource types is mapped to Terraform-shaped IR so the existing rules apply (camelCase keys become snake_case). Any other type is
reported as an error entry ("not assessed"), never silently treated as clean. Encrypted/secret values become `Unknown`.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict

from cloud.ir import Resource, Source, Unknown
from cloud.parsers.terraform import ParseResult

_PARSER = "cloud.parsers.pulumi 1"
_TYPES = {"aws:ec2/securityGroup:SecurityGroup": "aws_security_group",
          "aws:ec2/securityGroupRule:SecurityGroupRule": "aws_security_group_rule",
          "aws:vpc/securityGroupIngressRule:SecurityGroupIngressRule": "aws_vpc_security_group_ingress_rule"}
_CAMEL = re.compile(r"(?<=[a-z0-9])([A-Z])")
_SECRET_SIG = "4dabf18193072939515e22adb298388d"
MAX_DEPTH = 40
MAX_RESOURCES = 5000


def _snake(k: str) -> str:
    return _CAMEL.sub(r"_\1", k).lower()


def _value(v: Any, depth: int = 0) -> Any:
    if depth > MAX_DEPTH:
        return Unknown("nesting too deep")
    if isinstance(v, dict):
        if _SECRET_SIG in v or "ciphertext" in v:
            return Unknown("secret value: never read")
        return {_snake(str(k)): _value(x, depth + 1) for k, x in v.items()}
    if isinstance(v, list):
        return [_value(x, depth + 1) for x in v]
    return v


def parse_pulumi(path: str, text: str) -> ParseResult:
    result = ParseResult()
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError) as e:
        result.errors.append({"file": path, "error": f"invalid JSON: {str(e)[:200]}"})
        return result
    dep = doc.get("deployment") if isinstance(doc, dict) else None
    items = dep.get("resources") if isinstance(dep, dict) else None
    if not isinstance(items, list):
        result.errors.append({"file": path, "error": "no deployment.resources in the Pulumi export"})
        return result
    unmapped: Dict[str, int] = {}
    for i, item in enumerate(items):
        if not isinstance(item, dict) or str(item.get("type", "")).startswith("pulumi:"):
            continue
        ptype = str(item.get("type", ""))[:200]
        if ptype not in _TYPES:
            unmapped[ptype] = unmapped.get(ptype, 0) + 1
            continue
        if len(result.resources) >= MAX_RESOURCES:
            result.truncated = True
            break
        urn = str(item.get("urn", f"resource-{i}"))[:300]
        inputs = _value(item.get("inputs") or {})
        result.resources.append(Resource(
            provider="aws", service="pulumi", resource_type=_TYPES[ptype], logical_name=urn.rsplit("::", 1)[-1], address=urn,
            properties=inputs if isinstance(inputs, dict) else {}, source=Source(path, 1, 1, "pulumi", _PARSER),
            notes=["mapped from a Pulumi stack export (inputs only)"]).finalize())
    for t, n in sorted(unmapped.items()):
        result.errors.append({"file": path, "error": f"{n} resource(s) of Pulumi type {t!r} are not mapped to a rule and were not assessed"})
    return result
