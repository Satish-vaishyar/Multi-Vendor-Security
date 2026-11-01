"""Evidence + Compliance rule engines (OKF components 5-6, docs okf.md §9-12)."""
from __future__ import annotations
from typing import Any, Dict, List, Tuple
from .schemas import Control, Evidence, Finding


def _get(ir: Dict[str, Any], dotted: str) -> Any:
    cur: Any = ir
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def eval_op(observed: Any, operator: str, expected: Any) -> bool | None:
    op = operator.upper()
    if observed is None:
        return None  # UNKNOWN
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
    except Exception:
        return False
    return False


def eval_condition(ir: Dict[str, Any], cond: Dict[str, Any]) -> Tuple[bool | None, List[Evidence]]:
    """Supports {all:[...]}, {any:[...]}, or single {property, operator, value}."""
    if "all" in cond:
        results, evs = [], []
        for c in cond["all"]:
            r, e = eval_condition(ir, c)
            results.append(r)
            evs.extend(e)
        if any(r is False for r in results):
            return False, evs
        if any(r is None for r in results):
            return None, evs
        return True, evs
    if "any" in cond:
        results, evs = [], []
        for c in cond["any"]:
            r, e = eval_condition(ir, c)
            results.append(r)
            evs.extend(e)
        if any(r is True for r in results):
            return True, evs
        if any(r is None for r in results):
            return None, evs
        return False, evs
    obs = _get(ir, cond.get("property", ""))
    ok = eval_op(obs, cond.get("operator", "EQUALS"), cond.get("value"))
    ev = Evidence(control_id="", property=cond.get("property", ""),
                  observed_value=obs, expected_value=cond.get("value"),
                  operator=cond.get("operator", "EQUALS"),
                  status="PASS" if ok else ("FAIL" if ok is False else "UNKNOWN"))
    return ok, [ev]


def condition_properties(cond: Dict[str, Any]) -> List[str]:
    if "all" in cond or "any" in cond:
        return [p for c in cond.get("all", []) + cond.get("any", []) for p in condition_properties(c)]
    return [cond["property"]] if cond.get("property") else []


def control_applies(control: Control, vendor: str = "", platform: str = "") -> bool:
    """SCAP CPE-style applicability: a control with an empty `applies_to`
    applies to every target; otherwise the target's vendor/platform must be
    listed (case-insensitive). Non-applicable controls are never executed."""
    scope = control.applies_to or {}
    vendors = [str(v).lower() for v in (scope.get("vendors") or [])]
    platforms = [str(p).lower() for p in (scope.get("platforms") or [])]
    if vendors and str(vendor or "").lower() not in vendors:
        return False
    if platforms and str(platform or "").lower() not in platforms:
        return False
    return True


class ComplianceEngine:
    def __init__(self, controls: List[Control], remediation_index: Dict[str, Any] | None = None):
        self.controls = controls
        self.remediation = remediation_index or {}

    def evaluate(self, canonical_ir: Dict[str, Any], asset_id: str = "ASSET-001",
                 vendor: str = "", platform: str = "",
                 not_applicable: Dict[str, str] | None = None,
                 provenance: Dict[str, Dict[str, Any]] | None = None) -> List[Finding]:
        """not_applicable: {property: reason} declared by the vendor parser (property cannot exist on
        this platform/role). A control whose every property is non-applicable is NOT_APPLICABLE and leaves
        the score. provenance: {property: {basis, note, ...}} - copied onto each finding's evidence so
        reports can separate "observed in config" from "assumed platform default"."""
        na = not_applicable or {}
        prov = provenance or {}
        findings: List[Finding] = []
        for c in self.controls:
            props = condition_properties(c.condition or {})
            if props and all(p in na and _get(canonical_ir, p) is None for p in props):
                ev = Evidence(control_id=c.control_id, property=props[0], status="NOT_APPLICABLE",
                              note=na[props[0]])
                findings.append(Finding(
                    finding_id=f"F-{c.control_id}", engine="compliance", control_id=c.control_id,
                    title=c.title, severity=c.severity, status="NOT_APPLICABLE", asset_id=asset_id,
                    evidence=ev, remediation=self.remediation.get(c.control_id, {}),
                    frameworks=dict(c.frameworks)))
                continue
            if not control_applies(c, vendor, platform):
                ev = Evidence(control_id=c.control_id, property="",
                              status="NOT_APPLICABLE")
                findings.append(Finding(
                    finding_id=f"F-{c.control_id}",
                    engine="compliance", control_id=c.control_id, title=c.title,
                    severity=c.severity, status="NOT_APPLICABLE", asset_id=asset_id,
                    evidence=ev, remediation=self.remediation.get(c.control_id, {}),
                    frameworks=dict(c.frameworks),
                ))
                continue
            ok, evs = eval_condition(canonical_ir, c.condition or {})
            status = "PASS" if ok else ("FAIL" if ok is False else "UNKNOWN")
            ev = evs[0] if evs else Evidence(control_id=c.control_id, property="", status=status)
            ev.control_id = c.control_id
            used = [prov.get(e.property, {}) for e in evs if e.observed_value is not None]
            if used:   # one assumed default among the deciding properties makes the verdict "assumed"
                ev.basis = "default" if any(u.get("basis") == "default" for u in used) else "config"
                notes = [u.get("note") for u in used if u.get("note")]
                ev.note = notes[0] if notes else ""
            findings.append(Finding(
                finding_id=f"F-{c.control_id}",
                engine="compliance", control_id=c.control_id, title=c.title,
                severity=c.severity, status=status, asset_id=asset_id,
                evidence=ev, remediation=self.remediation.get(c.control_id, {}),
                frameworks=dict(c.frameworks),
            ))
        return findings

    @staticmethod
    def score(findings: List[Finding]) -> Dict[str, Any]:
        # NOT_APPLICABLE controls are reported but never scored (SCAP model:
        # only applicable checks form the denominator).
        scored = [f for f in findings if f.status != "NOT_APPLICABLE"]
        na = len(findings) - len(scored)
        total = len(scored)
        passed = sum(1 for f in scored if f.status == "PASS")
        failed = sum(1 for f in scored if f.status == "FAIL")
        unknown = total - passed - failed
        score = round(100.0 * passed / total, 1) if total else 0.0
        assessed = passed + failed
        def _basis(f: Finding) -> str:
            ev = f.evidence
            return getattr(ev, "basis", "") if not isinstance(ev, dict) else str(ev.get("basis", ""))
        assumed = sum(1 for f in scored if f.status in ("PASS", "FAIL") and _basis(f) == "default")
        sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in scored:
            if f.status == "FAIL" and f.severity in sev:
                sev[f.severity] += 1
        return {"compliance_score": score, "total": total, "passed": passed,
                "failed": failed, "unknown": unknown,
                "not_applicable": na,
                # How much of the verdict is evidence vs. gaps/assumptions (see docs/product_readiness_gaps.md P1-4)
                "assessed": assessed, "not_assessed": unknown, "assumed": assumed,
                "coverage_pct": round(100.0 * assessed / total, 1) if total else 0.0,
                "observed_pct": round(100.0 * (assessed - assumed) / total, 1) if total else 0.0,
                **sev}
