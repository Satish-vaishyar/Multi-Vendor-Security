"""Version Range Evaluator (cve_okf §7-8): is installed version in affected range?

Range: {start, start_inclusive, end, end_inclusive} with None = unbounded.
Returns True/False; None (unknown) only when installed version is missing.
"""
from __future__ import annotations
from typing import Any, Dict, Optional
from .version_normalizer import normalize


def in_range(installed: Optional[str], start: Optional[str], start_inclusive: bool,
             end: Optional[str], end_inclusive: bool) -> Optional[bool]:
    if not installed:
        return None
    iv = normalize(installed)
    if start:
        sv = normalize(start)
        if iv < sv or (iv == sv and not start_inclusive):
            return False
    if end:
        ev = normalize(end)
        if ev < iv or (iv == ev and not end_inclusive):
            return False
    return True


def match_record(installed: str, affected_versions: list) -> Dict[str, Any]:
    """affected_versions: [{start,start_inclusive,end,end_inclusive,fixed}...].

    Installed version is normalized ONCE (not per range entry) — this runs
    per KB record per component, so it matters once the KB holds thousands
    of real NVD records. Semantics identical to in_range().

    Misses still carry the first evaluated rule as matched_rule (never None):
    transparency UIs show the range that was actually checked instead of
    falling back to some other product's range.
    """
    first = affected_versions[0] if affected_versions else None
    miss = {"affected": False, "matched_rule": first,
            "fixed_version": first.get("fixed") if first else None}
    if not installed:
        return miss
    iv = normalize(installed)
    for r in affected_versions:
        start, end = r.get("start"), r.get("end")
        hit = True
        if start:
            sv = normalize(start)
            if iv < sv or (iv == sv and not r.get("start_inclusive", True)):
                hit = False
        if hit and end:
            ev = normalize(end)
            if ev < iv or (iv == ev and not r.get("end_inclusive", True)):
                hit = False
        if hit:
            return {"affected": True, "matched_rule": r,
                    "fixed_version": r.get("fixed")}
    return miss
