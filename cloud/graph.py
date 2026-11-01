"""Relationship graph and effective exposure (RTM S17; CAT §7.3, CFG-002).

A permissive rule on a security group only matters if something is attached to that group. The graph is built purely from
the references the parsers recorded; a group nothing in the uploaded files refers to is "unattached in these files", which
is NOT proof it is unused (another stack may attach it), so the verdict is reported as a note and never changes a finding's
evidence state. When modules or stacks could not be resolved, attachment is UNKNOWN instead of "unattached".
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from cloud.ir import Finding, Resource

_EXPOSABLE = ("aws_security_group", "AWS::EC2::SecurityGroup", "azurerm_network_security_group",
              "Microsoft.Network/networkSecurityGroups", "google_compute_firewall",
              "oci_core_network_security_group", "oci_core_security_list")
_SUFFIXES = (".id", ".arn", ".name", ".self_link", ".group_id", ".security_group_id")
_RULE_MARKERS = ("_rule", "SecurityGroupIngress", "SecurityGroupEgress", "securityRules")


def _is_rule(rtype: str) -> bool:
    return any(m in rtype for m in _RULE_MARKERS)


def _resolve(target: str, addresses: Sequence[str]) -> Optional[str]:
    """Map a reference expression (aws_security_group.web.id, Web) to a declared resource address."""
    t = target
    for s in _SUFFIXES:
        if t.endswith(s):
            t = t[: -len(s)]
            break
    best = None
    for a in addresses:
        base = a.split("[", 1)[0]
        if t == base or t.startswith(base + ".") or t.startswith(base + "["):
            if best is None or len(base) > len(best[0]):
                best = (base, a)
    if best is None:                                              # CloudFormation logical id
        for a in addresses:
            if a.rsplit(".", 1)[-1] == t:
                return a
    return best[1] if best else None


def build(resources: List[Resource]) -> Dict[str, Any]:
    addresses = [r.address for r in resources]
    by_addr = {r.address: r for r in resources}
    edges: List[Dict[str, str]] = []
    for r in resources:
        for rel in r.relationships:
            dst = _resolve(rel["target"], addresses)
            if dst and dst != r.address:
                edges.append({"from": r.address, "to": dst, "field": rel["field"], "type": rel["type"]})
    attached_by: Dict[str, List[str]] = {}
    for e in edges:
        src, dst = by_addr[e["from"]], by_addr[e["to"]]
        if dst.resource_type in _EXPOSABLE and not _is_rule(src.resource_type) and src.resource_type != dst.resource_type:
            attached_by.setdefault(dst.address, []).append(src.address)
    return {"edges": edges, "attached_by": {k: sorted(set(v)) for k, v in attached_by.items()}}


def attachment(graph: Dict[str, Any], resource: Resource, incomplete: bool) -> Optional[bool]:
    """True = something in the files attaches it; False = nothing does; None = cannot tell (unresolved modules/stacks)."""
    if graph["attached_by"].get(resource.address):
        return True
    return None if incomplete else False


def annotate(findings: List[Finding], resources: List[Resource], incomplete: bool) -> Dict[str, Any]:
    """Add an effective-exposure note to failed network findings on exposable groups; evidence states are untouched."""
    graph = build(resources)
    by_addr = {r.address: r for r in resources}
    summary = {"attached": 0, "unattached": 0, "unknown": 0}
    seen = set()
    for f in findings:
        r = by_addr.get(f.resource_address)
        if r is None or r.resource_type not in _EXPOSABLE or not f.control_id.startswith("CLOUD-NET-"):
            continue
        if f.evidence_state != "FAIL_STATIC":
            continue
        state = attachment(graph, r, incomplete)
        key = r.address
        if state is True:
            f.notes.append("Effective exposure: attached to " + ", ".join(graph["attached_by"][r.address][:3]) + ".")
        elif state is False:
            f.notes.append("Unattached in the uploaded files: the permissive rule is not an effective exposure here, "
                           "but another stack may attach this group.")
        else:
            f.notes.append("Attachment could not be determined (unresolved modules or stacks).")
        if key not in seen:
            seen.add(key)
            summary["attached" if state is True else "unattached" if state is False else "unknown"] += 1
    return {"edges": len(graph["edges"]), **summary}
