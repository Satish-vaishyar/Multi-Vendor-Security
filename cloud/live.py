"""Live assessment foundations (RTM S31/S32; CM-101..CM-110). NO cloud client is implemented here and nothing in this module
contacts a network: it holds the parts that must be right before any connector exists and that can be tested without an account.

* `ReadOnlyGuard` - the only way a connector may issue an API call; anything that is not a read of metadata is refused, and so is
  anything that reads secret material or object contents even though its name looks like a read.
* `Authorization` - the customer's written authorisation for one scope; expired, unscoped or over-privileged ones are refused.
* `Secret` - a credential wrapper that cannot be printed, logged, serialised or compared by accident.
* `reconcile` - merges static findings with live findings into PASS_LIVE / FAIL_LIVE / CONFLICT without ever turning UNKNOWN into a pass.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

_READ_PREFIX = {"aws": ("Get", "List", "Describe"), "azure": ("GET",), "gcp": ("get", "list", "aggregatedList", "testIamPermissions"),
                "oci": ("get", "list")}
# names that look like reads but return secret material or customer data
_SECRET_READS = re.compile(r"(secret|password|credential|token|decrypt|privatekey|private_key|accesskey|access_key|sas|connectionstring|"
                           r"getobject|getparameter|listkeys|getkeys|exportcertificate)", re.I)
MAX_AUTH_DAYS = 90


class LiveRefused(PermissionError):
    """The requested live operation is not allowed."""


class Secret:
    """Holds a credential. Printing, logging, formatting, pickling and JSON encoding all show a mask, never the value."""
    __slots__ = ("_v",)

    def __init__(self, value: str):
        object.__setattr__(self, "_v", value)

    def reveal(self) -> str:
        """The one deliberate way to read it, for the connector that signs a request."""
        return self._v

    def __repr__(self) -> str:
        return "Secret(****)"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return "****"

    def __reduce__(self):
        raise TypeError("a Secret cannot be pickled")

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("a Secret is immutable")

    def __eq__(self, other: object) -> bool:
        return False

    __hash__ = None  # type: ignore[assignment]


class ReadOnlyGuard:
    def __init__(self, provider: str):
        if provider not in _READ_PREFIX:
            raise LiveRefused(f"no read-only policy for provider {provider!r}")
        self.provider = provider

    def check(self, operation: str) -> str:
        op = operation.strip()
        if not op or not op.startswith(_READ_PREFIX[self.provider]):
            raise LiveRefused(f"{operation!r} is not a read-only operation")
        if _SECRET_READS.search(op):
            raise LiveRefused(f"{operation!r} can return secret material or customer data and is never called")
        return op


@dataclass(frozen=True)
class Authorization:
    org_id: str
    provider: str
    scope: str                      # account id / subscription id / project id / tenancy ocid
    role_ref: str                   # the read-only role the customer created (a reference, not a credential)
    authorised_by: str
    expires_at: datetime
    read_only_attested: bool = False
    regions: Sequence[str] = field(default_factory=tuple)

    def problems(self, now: Optional[datetime] = None) -> List[str]:
        now = now or datetime.now(timezone.utc)
        out = []
        for name in ("org_id", "provider", "scope", "role_ref", "authorised_by"):
            if not str(getattr(self, name) or "").strip():
                out.append(f"{name} is required")
        if self.provider not in _READ_PREFIX:
            out.append("unsupported provider")
        if not self.read_only_attested:
            out.append("the customer must attest that the role is read-only")
        if self.expires_at.tzinfo is None or self.expires_at <= now:
            out.append("authorisation has expired or has no timezone")
        elif (self.expires_at - now).days > MAX_AUTH_DAYS:
            out.append(f"authorisation may last at most {MAX_AUTH_DAYS} days")
        return out

    def require(self, now: Optional[datetime] = None) -> "Authorization":
        problems = self.problems(now)
        if problems:
            raise LiveRefused("; ".join(problems))
        return self




def _key(f: Dict[str, Any]) -> tuple:
    return (f.get("control_id"), f.get("resource_key") or f.get("resource_address"))


def reconcile(static: Sequence[Dict[str, Any]], live: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Combine static and live findings. Agreement is confirmed as *_LIVE; disagreement is CONFLICT (neither side wins silently);
    live-only findings are kept; static-only findings keep their static state; an UNKNOWN live result never overrides static."""
    live_by = {_key(f): f for f in live}
    out: List[Dict[str, Any]] = []
    for s in static:
        l = live_by.pop(_key(s), None)
        if l is None or l.get("evidence_state") not in ("PASS_LIVE", "FAIL_LIVE"):
            out.append({**s, "notes": list(s.get("notes") or []) + (["live evidence unavailable for this check"] if l is not None else [])})
            continue
        s_state, l_state = s.get("evidence_state"), l["evidence_state"]
        static_pass, static_fail = s_state == "PASS_STATIC", s_state == "FAIL_STATIC"
        if (static_pass and l_state == "FAIL_LIVE") or (static_fail and l_state == "PASS_LIVE"):
            out.append({**s, "evidence_state": "CONFLICT",
                        "notes": list(s.get("notes") or []) + [f"static analysis says {s_state}, the live environment says {l_state}"]})
        else:
            out.append({**s, "evidence_state": l_state, "notes": list(s.get("notes") or []) + ["confirmed by live evidence"]})
    out.extend(live_by.values())
    return out
