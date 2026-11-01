"""Engine 3 - Security Analytics (arch.md §19-20): a YAML rule set evaluated against the canonical IR.

Two rule kinds live in ``rules/security_rules.yaml``:
  * signals - one posture issue each (weak auth, exposure, permissive ACL, legacy service, logging gap ...);
  * paths   - attack-path combinations ("internet-facing management + no MFA") that explain *why* several
              moderate signals together are worse than each alone, listing their contributors.

Every result carries ``rule_id``, an explanation, a fix, and ``basis`` (``observed`` when the triggering
properties were read from the configuration, ``assumed`` when they are platform defaults the device
reports no explicit line for). Assumed-only hits are downgraded one severity level so a guessed default can
never produce a CRITICAL on its own.

``analyze(..., compliance_failed=...)`` flags signals whose property already fails a compliance control as
``duplicates_compliance`` so the audit does not report the same problem twice.
"""
from __future__ import annotations
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

import yaml

RULES_FILE = Path(__file__).parent / "rules" / "security_rules.yaml"
_SEV_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
_DEDUCT = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2}
_PATH_DEDUCT = 15
_lock = threading.Lock()
_cache: Dict[str, Any] = {"mtime": None, "rules": None}


class RuleError(ValueError):
    pass


def load_rules(path: Path = RULES_FILE) -> Dict[str, List[Dict[str, Any]]]:
    """Parse + validate the rule file (cached by mtime). Raises RuleError on a malformed rule."""
    with _lock:
        mtime = path.stat().st_mtime_ns
        if _cache["mtime"] == mtime and _cache["rules"] is not None and path == RULES_FILE:
            return _cache["rules"]
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        rules = {"signals": list(raw.get("signals") or []), "paths": list(raw.get("paths") or [])}
        seen: Set[str] = set()
        for r in rules["signals"] + rules["paths"]:
            rid = r.get("id")
            if not rid or rid in seen:
                raise RuleError(f"rule id missing or duplicated: {rid!r}")
            seen.add(rid)
            if r.get("severity") not in _SEV_ORDER:
                raise RuleError(f"{rid}: invalid severity {r.get('severity')!r}")
        for r in rules["signals"]:
            _validate(r.get("when"), r["id"])
        for r in rules["paths"]:
            if not r.get("signals"):
                raise RuleError(f"{r['id']}: a path needs signals")
            for s in r["signals"]:
                _validate(s, r["id"])
            if r.get("requires") is not None:
                _validate(r["requires"], r["id"])
        if path == RULES_FILE:
            _cache.update(mtime=mtime, rules=rules)
        return rules


_LEAF_OPS = ("is_true", "is_false", "missing", "present", "eq", "ne", "gte", "lt", "in")


def _validate(cond: Any, rid: str) -> None:
    if not isinstance(cond, dict) or not cond:
        raise RuleError(f"{rid}: empty or invalid condition")
    if "all" in cond or "any" in cond:
        for c in cond.get("all", []) + cond.get("any", []):
            _validate(c, rid)
    elif "not" in cond:
        _validate(cond["not"], rid)
    else:
        if "prop" not in cond or not any(op in cond for op in _LEAF_OPS):
            raise RuleError(f"{rid}: bad leaf {cond}")


def _leaf(cond: Dict[str, Any], flat: Dict[str, Any]) -> bool:
    v = flat.get(cond["prop"])
    if "is_true" in cond:
        return (v is True) == bool(cond["is_true"])
    if "is_false" in cond:
        return (v is False) == bool(cond["is_false"])
    if "missing" in cond:
        return (v is None) == bool(cond["missing"])
    if "present" in cond:
        return (v is not None) == bool(cond["present"])
    if "eq" in cond:
        return v == cond["eq"]
    if "ne" in cond:
        return v is not None and v != cond["ne"]
    if "in" in cond:
        return v in cond["in"]
    try:
        if "gte" in cond:
            return v is not None and v >= cond["gte"]
        if "lt" in cond:
            return v is not None and v < cond["lt"]
    except TypeError:
        return False
    return False


def evaluate(cond: Dict[str, Any], flat: Dict[str, Any]) -> bool:
    if "all" in cond:
        return all(evaluate(c, flat) for c in cond["all"])
    if "any" in cond:
        return any(evaluate(c, flat) for c in cond["any"])
    if "not" in cond:
        return not evaluate(cond["not"], flat)
    return _leaf(cond, flat)


def props_of(cond: Any) -> List[str]:
    if not isinstance(cond, dict):
        return []
    if "prop" in cond:
        return [cond["prop"]]
    out: List[str] = []
    for key in ("all", "any"):
        for c in cond.get(key, []):
            out += props_of(c)
    if "not" in cond:
        out += props_of(cond["not"])
    return list(dict.fromkeys(out))


def _basis(props: Iterable[str], flat: Dict[str, Any], provenance: Optional[Dict[str, Any]]) -> str:
    """'assumed' when every triggering property that has a value is a platform default, else 'observed'."""
    present = [p for p in props if flat.get(p) is not None]
    if not present or not provenance:
        return "observed"
    return "assumed" if all((provenance.get(p) or {}).get("basis") == "default" for p in present) else "observed"


def _lower(sev: str) -> str:
    return _SEV_ORDER[max(0, _SEV_ORDER.index(sev) - 1)]


def analyze(flat: Dict[str, Any], asset_id: str = "", provenance: Optional[Dict[str, Any]] = None,
            compliance_failed: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    rules = load_rules()
    failed = set(compliance_failed or [])
    anomalies: List[Dict[str, Any]] = []
    for r in rules["signals"]:
        if not evaluate(r["when"], flat):
            continue
        prop = r.get("prop") or props_of(r["when"])[0]
        basis = _basis(props_of(r["when"]), flat, provenance)
        sev = _lower(r["severity"]) if basis == "assumed" else r["severity"]
        anomalies.append({"rule_id": r["id"], "type": r["type"], "property": prop, "severity": sev,
                          "asset_id": asset_id, "detail": r.get("detail", ""), "why": r.get("why", ""),
                          "fix": r.get("fix", ""), "basis": basis,
                          "duplicates_compliance": prop in failed})
    patterns: List[Dict[str, Any]] = []
    for r in rules["paths"]:
        if r.get("requires") is not None and not evaluate(r["requires"], flat):
            continue
        hits = [s for s in r["signals"] if evaluate(s, flat)]
        if len(hits) < int(r.get("min_signals", 1)):
            continue
        active = [p for s in hits for p in props_of(s)] + props_of(r.get("requires"))
        triggered = [p for p in dict.fromkeys(active) if flat.get(p) is not None or p in props_of(r.get("requires"))]
        basis = _basis(triggered, flat, provenance)
        sev = _lower(r["severity"]) if basis == "assumed" else r["severity"]
        patterns.append({"rule_id": r["id"], "pattern": r["name"], "severity": sev, "detail": r.get("detail", ""),
                         "contributors": r.get("contributors", []), "active_signals": len(hits),
                         "fix": r.get("fix", ""), "basis": basis,
                         "evidence": {p: flat.get(p) for p in dict.fromkeys(props_of(r.get("requires")) +
                                                                            [q for s in hits for q in props_of(s)])}})
    score = 100
    for a in anomalies:
        score -= _DEDUCT.get(a["severity"], 5)
    score -= _PATH_DEDUCT * len(patterns)
    return {"risk_score": max(0, min(100, score)), "anomalies": anomalies, "patterns": patterns,
            "count": len(anomalies) + len(patterns), "rules_version": f"{len(rules['signals'])}s/{len(rules['paths'])}p"}
