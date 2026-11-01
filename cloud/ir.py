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


# ---------------------------------------------------------------- S11: findings, serialisation, validation
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@dataclass
class Finding:
    """One rule result for one resource. Never contains a raw secret (see Resource.to_dict redaction)."""
    control_id: str
    title: str
    severity: str
    evidence_state: str
    resource_address: str
    resource_type: str
    provider: str
    evidence: List[Dict[str, Any]]
    source: Dict[str, Any]
    rule_version: str = ""
    engine: str = "orbit"
    frameworks: List[Dict[str, Any]] = field(default_factory=list)
    remediation: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    exception: Dict[str, Any] = field(default_factory=dict)      # set by exceptions.apply_exceptions; never changes evidence_state

    @property
    def dedupe_key(self) -> str:
        import hashlib
        raw = f"{self.control_id}|{self.resource_address}|{self.source.get('file', '')}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]

    def to_dict(self) -> Dict[str, Any]:
        return {"control_id": self.control_id, "title": self.title, "severity": self.severity,
                "evidence_state": self.evidence_state, "resource_address": self.resource_address,
                "resource_type": self.resource_type, "provider": self.provider, "evidence": jsonable(self.evidence),
                "source": self.source, "rule_version": self.rule_version, "engine": self.engine,
                "frameworks": self.frameworks, "remediation": self.remediation, "notes": self.notes,
                "exception": self.exception, "dedupe_key": self.dedupe_key}


def jsonable(value: Any, redact: bool = False) -> Any:
    """JSON-safe copy. Unknown -> {"$unknown": reason}, Ref -> {"$ref": target}. With redact=True every string leaf is
    passed through the secret scanner first, so stored/exported data never carries a credential."""
    if isinstance(value, Unknown):
        return {"$unknown": value.reason}
    if isinstance(value, Ref):
        return {"$ref": value.target}
    if isinstance(value, dict):
        return {str(k): jsonable(v, redact) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(v, redact) for v in value]
    if isinstance(value, str) and redact:
        from cloud import secret_scan
        return secret_scan.redact(value)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def resource_to_dict(r: Resource, scope: Dict[str, Any] = None) -> Dict[str, Any]:
    """The normalised Cloud Resource IR record (CAT 7.2). Secrets are redacted from every string."""
    scope = scope or {}
    sc = {"organization": None, "account_or_tenant": None, "project_or_subscription": None, "region": None,
          "compartment_or_resource_group": None, **scope}
    return {
        "resource_key": f"{r.provider}:{sc['account_or_tenant'] or '-'}:{sc['region'] or '-'}:{r.address}",
        "provider": r.provider, "service": r.service, "resource_type": r.resource_type, "kind": r.kind,
        "logical_name": r.logical_name, "address": r.address, "physical_id": None, "scope": sc,
        "properties": jsonable(r.properties, redact=True), "relationships": r.relationships,
        "source": {"file": r.source.file, "line_start": r.source.line_start, "line_end": r.source.line_end,
                   "format": r.source.format, "parser_version": r.source.parser},
        "evidence_mode": r.evidence_mode, "confidence": r.confidence, "unknown_fields": r.unknown_fields,
        "notes": r.notes, "provider_raw": jsonable(r.provider_raw, redact=True)}


def validate_resource(r: Resource) -> List[str]:
    """Return a list of problems; an empty list means the record is well-formed."""
    problems = []
    for name in ("provider", "resource_type", "address"):
        if not getattr(r, name):
            problems.append(f"missing {name}")
    if not 0.0 <= r.confidence <= 1.0:
        problems.append("confidence outside 0..1")
    if r.evidence_mode not in ("static", "live"):
        problems.append("invalid evidence_mode")
    if not r.source.file:
        problems.append("missing source file")
    if r.source.line_start < 0 or r.source.line_end < r.source.line_start:
        problems.append("invalid source line range")
    return problems
