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


class ComplianceEngine:
    def __init__(self, controls: List[Control], remediation_index: Dict[str, Any] | None = None):
        self.controls = controls
        self.remediation = remediation_index or {}

    def evaluate(self, canonical_ir: Dict[str, Any], asset_id: str = "ASSET-001") -> List[Finding]:
        findings: List[Finding] = []
        for c in self.controls:
            ok, evs = eval_condition(canonical_ir, c.condition or {})
            status = "PASS" if ok else ("FAIL" if ok is False else "UNKNOWN")
            ev = evs[0] if evs else Evidence(control_id=c.control_id, property="", status=status)
            ev.control_id = c.control_id
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
        total = len(findings)
        passed = sum(1 for f in findings if f.status == "PASS")
        failed = sum(1 for f in findings if f.status == "FAIL")
        unknown = total - passed - failed
        score = round(100.0 * passed / total, 1) if total else 0.0
        sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            if f.status == "FAIL" and f.severity in sev:
                sev[f.severity] += 1
        return {"compliance_score": score, "total": total, "passed": passed,
                "failed": failed, "unknown": unknown, **sev}
