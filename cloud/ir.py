"""Cloud Resource IR (RTM S08 introduces the types; S11 adds serialisation and validation).

Every parser produces `Resource` objects with provenance. Values that cannot be known from the uploaded files are
`Unknown` (never guessed, never treated as PASS); references to other resources are `Ref`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Tuple

EVIDENCE_STATES = ("PASS_STATIC", "FAIL_STATIC", "UNKNOWN_STATIC", "NOT_APPLICABLE",
                   "PASS_LIVE", "FAIL_LIVE", "UNKNOWN_LIVE", "CONFLICT")


@dataclass(frozen=True)
class Unknown:
    """A value that is omitted, computed, inherited or dynamically generated in the uploaded files."""
    reason: str
    expr: str = ""

    def __repr__(self) -> str:
        return f"Unknown({self.reason!r})"


@dataclass(frozen=True)
class Ref:
    """A reference to another declared resource, e.g. aws_s3_bucket.b.id (used to build the relationship graph)."""
    target: str

    def __repr__(self) -> str:
        return f"Ref({self.target!r})"


@dataclass
class Source:
    file: str
    line_start: int = 0
    line_end: int = 0
    format: str = ""
    parser: str = ""


@dataclass
class Resource:
    provider: str
    service: str
    resource_type: str                  # native type, e.g. aws_security_group / AWS::S3::Bucket
    logical_name: str
    address: str                        # unique within a scan, e.g. module.net.aws_security_group.web[0]
    properties: Dict[str, Any]
    source: Source
    kind: str = "resource"              # "resource" | "data"
    evidence_mode: str = "static"
    confidence: float = 1.0
    notes: List[str] = field(default_factory=list)
    relationships: List[Dict[str, str]] = field(default_factory=list)
    unknown_fields: List[str] = field(default_factory=list)
    provider_raw: Dict[str, Any] = field(default_factory=dict)

    def finalize(self) -> "Resource":
        """Derive unknown_fields and Ref relationships from the property tree."""
        self.unknown_fields = sorted({p for p, v in walk(self.properties) if isinstance(v, Unknown)})
        seen = set()
        for p, v in walk(self.properties):
            if isinstance(v, Ref) and (p, v.target) not in seen:
                seen.add((p, v.target))
                self.relationships.append({"type": "REFERENCES", "field": p, "target": v.target})
        return self


def walk(value: Any, path: str = "") -> Iterator[Tuple[str, Any]]:
    """Yield (dotted_path, leaf) for every leaf in a nested dict/list tree."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield from walk(v, f"{path}.{k}" if path else str(k))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from walk(v, f"{path}[{i}]")
    else:
        yield path, value


def as_list(value: Any) -> List[Any]:
    """HCL/JSON blocks may appear as one object or a list of objects; rules should not care which."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]
