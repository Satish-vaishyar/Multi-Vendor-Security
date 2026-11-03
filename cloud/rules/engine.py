"""Deterministic rule engine (RTM S12; CM-003, CM-081, CM-094).

Same condition DSL and operator semantics as the network OKF engine (`all` / `any` / `{property, operator, value}`,
a missing observed value is UNKNOWN), re-implemented here so the sandboxed scanner image does not need pydantic or the
okf sources; `tests/test_parity.py` proves the two agree. An LLM is never involved in a verdict.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from cloud.ir import Finding, Resource
from cloud.rules import extractors
from cloud.rules.pack import Pack

STATE = {True: "PASS_STATIC", False: "FAIL_STATIC", None: "UNKNOWN_STATIC"}


def eval_op(observed: Any, operator: str, expected: Any) -> Optional[bool]:
    op = operator.upper()
    if observed is None:
        return None
    try:
        if op == "EQUALS":
            return observed == expected
        if op == "NOT_EQUALS":
            return observed != expected
        if op == "GTE":
            return float(observed) >= float(expected)
        if op == "LTE":
            return float(observed) <= float(expected)
        if op == "GT":
            return float(observed) > float(expected)
        if op == "LT":
            return float(observed) < float(expected)
        if op == "IN":
            return observed in (expected or [])
        if op == "NOT_IN":
            return observed not in (expected or [])
        if op == "CONTAINS":
            return str(expected) in str(observed)
        if op == "EXISTS":
            return observed is not None
    except Exception:                                   # noqa: BLE001 - same behaviour as the network engine
        return False
    return False


def eval_condition(props: Dict[str, Any], cond: Dict[str, Any]) -> Tuple[Optional[bool], List[Dict[str, Any]]]:
    """props is the flat {property_id: value} map of ONE resource."""
    for key, combine_any in (("all", False), ("any", True)):
        if key in cond:
            results, evidence = [], []
            for c in cond[key]:
                r, e = eval_condition(props, c)
                results.append(r)
                evidence.extend(e)
            decisive = True if combine_any else False
            if any(r is decisive for r in results):
                return decisive, evidence
            return (None if any(r is None for r in results) else (not decisive)), evidence
    prop = cond.get("property", "")
    observed = props.get(prop)
    ok = eval_op(observed, cond.get("operator", "EQUALS"), cond.get("value"))
    return ok, [{"property": prop, "operator": cond.get("operator", "EQUALS"), "expected": cond.get("value"),
                 "observed": observed, "status": "PASS" if ok else ("FAIL" if ok is False else "UNKNOWN")}]


def map_resource(resource: Resource, pack: Pack) -> Dict[str, Optional[bool]]:
    """Canonical properties declared for this resource. A key mapped to None means 'applicable but unknown'."""
    out: Dict[str, Any] = {}
    for m in pack.by_type.get(resource.resource_type, []):
        for pid, spec in (m.get("properties") or {}).items():
            out[pid] = extractors.eval_spec(spec, resource.properties)
        for name in m.get("extractors") or []:
            out.update(extractors.REGISTRY[name](resource))
    return out


def _condition_props(cond: Dict[str, Any]) -> List[str]:
    from cloud.rules.pack import condition_properties
    return condition_properties(cond)


def evaluate_resource(resource: Resource, pack: Pack) -> List[Finding]:
    props = map_resource(resource, pack)
    findings: List[Finding] = []
    for control in pack.controls:
        needed = _condition_props(control.condition)
        if not needed or not all(p in props for p in needed):
            continue                                    # not applicable to this resource: no finding
        ok, evidence = eval_condition(props, control.condition)
        notes = list(resource.notes)
        if resource.confidence < 1.0:
            notes.append("reduced confidence: the resource is conditional or partially known")
        findings.append(Finding(
            control_id=control.id, title=control.name, severity=control.severity, evidence_state=STATE[ok],
            resource_address=resource.address, resource_type=resource.resource_type, provider=resource.provider,
            evidence=evidence, source={"file": resource.source.file, "line_start": resource.source.line_start,
                                       "line_end": resource.source.line_end, "format": resource.source.format},
            rule_version=control.logic_version, frameworks=control.frameworks, remediation=control.remediation, notes=notes))
    return findings


@dataclass
class EvalResult:
    findings: List[Finding]
    coverage: Dict[str, Any] = field(default_factory=dict)


def evaluate(resources: List[Resource], pack: Pack) -> EvalResult:
    findings: List[Finding] = []
    unsupported: Counter = Counter()
    with_rules = 0
    for r in resources:
        if r.kind != "resource":
            continue
        if r.resource_type not in pack.by_type:
            unsupported[r.resource_type] += 1
            continue
        got = evaluate_resource(r, pack)
        with_rules += bool(got)
        findings.extend(got)
    states = Counter(f.evidence_state for f in findings)
    coverage = {"resources_parsed": len(resources), "resources_with_supported_type": len(resources) - sum(unsupported.values()),
                "resources_with_findings_or_passes": with_rules, "unsupported_resource_types": dict(sorted(unsupported.items())),
                "rules_in_pack": len(pack.controls), "rule_evaluations": len(findings), "states": dict(states),
                "pack_version": pack.version}
    return EvalResult(findings, coverage)
