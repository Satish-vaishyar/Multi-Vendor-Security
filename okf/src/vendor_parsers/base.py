"""Shared plumbing for the structured (context-aware) vendor parsers.

A parser turns raw config text into *facts*: canonical property -> value, each with
provenance. Two kinds of facts exist and the distinction is surfaced everywhere
(evidence, reports, coverage):

  basis="config"   the value was read from an actual line of the configuration
  basis="default"  the line is absent and the value follows from the documented
                   platform default (e.g. Junos has no telnet service unless configured).
                   These carry a note and lower confidence and can be filtered out.

Anything a parser cannot determine is simply NOT set, so the compliance engine reports
UNKNOWN / "not assessed" instead of guessing a PASS.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set

DEFAULT_CONFIDENCE = 0.6


@dataclass
class ParseResult:
    vendor: str
    platform: str
    flat: Dict[str, Any] = field(default_factory=dict)
    provenance: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    consumed: Set[int] = field(default_factory=set)   # 1-based line numbers the parser understood
    not_applicable: Dict[str, str] = field(default_factory=dict)   # property -> why it does not exist here
    notes: List[str] = field(default_factory=list)


class Facts:
    """Accumulator with 'first real evidence wins, defaults never override evidence' semantics."""

    def __init__(self, vendor: str, platform: str, lines: List[str]):
        self.res = ParseResult(vendor=vendor, platform=platform)
        self.lines = lines

    # -- reading ---------------------------------------------------------------
    def text(self, line_no: Optional[int]) -> str:
        if line_no and 1 <= line_no <= len(self.lines):
            return self.lines[line_no - 1].strip()
        return ""

    def has(self, prop: str) -> bool:
        return prop in self.res.flat

    def is_default(self, prop: str) -> bool:
        return self.res.provenance.get(prop, {}).get("basis") == "default"

    def get(self, prop: str, default: Any = None) -> Any:
        return self.res.flat.get(prop, default)

    # -- writing ---------------------------------------------------------------
    def put(self, prop: str, value: Any, line_no: Optional[int] = None, *, override: bool = False,
            note: str = "", targets: Optional[List[Dict[str, Any]]] = None) -> None:
        """Record a value observed in the configuration."""
        if prop in self.res.flat and not override and not self.is_default(prop):
            return
        self.res.flat[prop] = value
        self.res.provenance[prop] = {
            "line": self.text(line_no), "line_no": line_no, "source": f"parser:{self.res.vendor}",
            "confidence": 1.0, "basis": "config", **({"note": note} if note else {}),
            **({"targets": targets} if targets else {})}
        if line_no:
            self.res.consumed.add(line_no)

    def default(self, prop: str, value: Any, note: str, targets: Optional[List[Dict[str, Any]]] = None) -> None:
        """Record a documented platform default - only when nothing was observed."""
        if prop in self.res.flat:
            return
        self.res.flat[prop] = value
        self.res.provenance[prop] = {
            "line": "", "line_no": None, "source": f"parser:{self.res.vendor}",
            "confidence": DEFAULT_CONFIDENCE, "basis": "default", "note": note,
            **({"targets": targets} if targets else {})}

    def worst(self, prop: str, value: Any, line_no: Optional[int], note: str = "") -> None:
        """Latest-wins for 'any occurrence is bad' booleans: a bad finding replaces a good one."""
        self.put(prop, value, line_no, override=True, note=note)

    def na(self, props: Iterable[str], reason: str) -> None:
        """Declare properties that cannot exist on this platform/role (never overrides a real fact)."""
        for p in props:
            if p not in self.res.flat:
                self.res.not_applicable[p] = reason

    def consume(self, *line_nos: Optional[int]) -> None:
        for n in line_nos:
            if n:
                self.res.consumed.add(n)

    def result(self) -> ParseResult:
        return self.res


# Property groups used by several parsers to declare non-applicability.
IOS_ONLY = ("SERVICE.PASSWORD_ENCRYPTION", "SERVICE.PAD_DISABLED", "SERVICE.FINGER_DISABLED",
            "DNS.LOOKUP_DISABLED", "IP.SOURCE_ROUTE_DISABLED", "IP.DIRECTED_BROADCAST_DISABLED")
SWITCH_ONLY = ("DHCP.SNOOPING", "PORT_SECURITY.ENABLED", "STP.BPDU_GUARD")
ROUTING_AUTH = ("ROUTING.AUTH_ENABLED", "ROUTING.OSPF_AUTH", "ROUTING.BGP_AUTH")


def run_extractors(facts: "Facts", fns) -> ParseResult:
    """Run every extractor; one that raises must not discard the others' facts. The failure is
    NOT silent: it is recorded in `notes` (surfaced in the audit's parser summary and logs)."""
    import logging
    for fn in fns:
        try:
            fn()
        except Exception as e:                       # noqa: BLE001 - deliberate containment, recorded below
            msg = f"{getattr(fn, '__name__', 'extractor')} failed: {type(e).__name__}: {e}"
            facts.res.notes.append(msg)
            logging.getLogger("vendor_parsers").warning("%s [%s]", msg, facts.res.vendor)
    return facts.result()


WELL_KNOWN_COMMUNITIES = ("public", "private")


def community_ref(name: str, line_no: Optional[int]) -> str:
    """Target name for an SNMP community. A community string is a credential, so it must never be copied
    into stored audit data: only the well-known defaults are kept literally; anything else becomes a
    reference to the config line the operator can read it from (`<COMMUNITY_L119>`)."""
    if name.lower() in WELL_KNOWN_COMMUNITIES:
        return name
    return f"<COMMUNITY_L{line_no}>" if line_no else "<COMMUNITY>"


def numbered(text: str) -> List[str]:
    """Split keeping a stable 1-based numbering identical to the caller's text.splitlines()."""
    return text.splitlines()


def any_match(items: Iterable[str], needles: Iterable[str]) -> bool:
    low = [i.lower() for i in items]
    return any(n in x for n in needles for x in low)
