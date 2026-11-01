"""Risk-acceptance exceptions with owner, justification, expiry and separation of duties (RTM S21; CM-083).

An exception never changes the evidence state (a violation stays a violation); it annotates the finding as accepted
while the exception is APPROVED and unexpired. Once it expires the annotation turns EXPIRED and the finding counts again.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from cloud.ir import Finding

MAX_EXCEPTION_DAYS = 365
STATUSES = ("PENDING", "APPROVED", "REJECTED", "REVOKED")


def _parse(ts: Any) -> Optional[datetime]:
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    try:
        d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _structural_problems(ex: Dict[str, Any]) -> List[str]:
    """Problems independent of the clock: required fields, a real justification, a parseable expiry, separation of duties."""
    problems = []
    for req in ("rule_id", "owner", "justification"):
        if not str(ex.get(req) or "").strip():
            problems.append(f"{req} is required")
    if len(str(ex.get("justification") or "").strip()) < 20:
        problems.append("justification must explain the risk acceptance (at least 20 characters)")
    if _parse(ex.get("expires_at")) is None:
        problems.append("expires_at is required (ISO 8601)")
    if ex.get("status") == "APPROVED":
        if not ex.get("approved_by"):
            problems.append("an approved exception needs approved_by")
        elif ex.get("approved_by") == ex.get("requested_by"):
            problems.append("the approver must differ from the requester")
    return problems


def validate_exception(ex: Dict[str, Any], now: Optional[datetime] = None) -> List[str]:
    """Problems that make an exception REQUEST unacceptable now (empty list = acceptable)."""
    now = now or datetime.now(timezone.utc)
    problems = _structural_problems(ex)
    expires = _parse(ex.get("expires_at"))
    if expires is not None and expires <= now:
        problems.append("expires_at must be in the future")
    elif expires is not None and expires > now + timedelta(days=MAX_EXCEPTION_DAYS):
        problems.append(f"expiry may be at most {MAX_EXCEPTION_DAYS} days away")
    return problems


def _matches(ex: Dict[str, Any], f: Finding) -> bool:
    if ex.get("rule_id") != f.control_id:
        return False
    target = ex.get("resource_key") or ex.get("resource_address")
    return not target or target in (f.resource_address, f"{f.provider}:-:-:{f.resource_address}")


def apply_exceptions(findings: List[Finding], exceptions: List[Dict[str, Any]], now: Optional[datetime] = None) -> List[Finding]:
    """Return copies of `findings` annotated with the best matching exception. Evidence states are never altered."""
    now = now or datetime.now(timezone.utc)
    out: List[Finding] = []
    for f in findings:
        note: Dict[str, Any] = {}
        for ex in exceptions:
            if ex.get("status") != "APPROVED" or not _matches(ex, f) or _structural_problems(ex):
                continue
            expires = _parse(ex.get("expires_at"))
            status = "ACTIVE" if expires and expires > now else "EXPIRED"
            if not note or status == "ACTIVE":
                note = {"status": status, "exception_id": ex.get("exception_id", ""), "owner": ex["owner"],
                        "expires_at": expires.isoformat() if expires else "", "justification": ex["justification"]}
            if status == "ACTIVE":
                break
        out.append(replace(f, exception=note) if note else f)
    return out
