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
    """affected_versions: [{start,start_inclusive,end,end_inclusive,fixed}...]."""
    for r in affected_versions:
        hit = in_range(installed, r.get("start"), r.get("start_inclusive", True),
                       r.get("end"), r.get("end_inclusive", True))
        if hit:
            return {"affected": True, "matched_rule": r,
                    "fixed_version": r.get("fixed")}
    return {"affected": False, "matched_rule": None,
            "fixed_version": affected_versions[0].get("fixed") if affected_versions else None}
