"""Pydantic schemas — single source of truth for OKF objects (docs okf.md §5-6, api.md §30)."""
from __future__ import annotations
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
Op = Literal["EQUALS", "NOT_EQUALS", "GTE", "LTE", "GT", "LT", "IN", "NOT_IN", "CONTAINS", "EXISTS"]
FindingStatus = Literal["PASS", "FAIL", "PARTIAL", "UNKNOWN", "NOT_APPLICABLE"]


class CanonicalProperty(BaseModel):
    property_id: str
    category: str
    datatype: Literal["boolean", "enum", "integer", "string", "list"] = "boolean"
    allowed_values: List[Any] = []
    security_level: Severity = "MEDIUM"
    description: str = ""
    default_expected: Any = None


class Condition(BaseModel):
    property: str
    operator: Op = "EQUALS"
    value: Any = None


class Control(BaseModel):
    control_id: str
    title: str
    description: str = ""
    category: str = "general"
    severity: Severity = "MEDIUM"
    version: str = "1.0"
    frameworks: Dict[str, Any] = Field(default_factory=dict)  # e.g. {"NIST": "AC-17"} or {"ISO27001": ["A.8.20", "A.8.21"]}
    condition: Dict[str, Any] = Field(default_factory=dict)   # {all:[...]} / {any:[...]} / single condition
    # Platform applicability (SCAP CPE-style): which device vendors/platforms
    # this control can ever apply to. Empty lists = applies to all targets.
    # The engine skips non-matching targets as NOT_APPLICABLE (never scored).
    applies_to: Dict[str, List[str]] = Field(default_factory=dict)
    evidence_type: str = "CONFIGURATION"
    remediation_id: Optional[str] = None
    references: List[str] = []


class Framework(BaseModel):
    framework_id: str
    name: str
    version: str = ""
    publisher: str = ""
    source: str = ""
    control_ids: List[str] = []


class CrosswalkEntry(BaseModel):
    canonical_property: str
    mappings: List[Dict[str, str]] = []  # [{framework, control_id}]


class Evidence(BaseModel):
    control_id: str
    property: str
    observed_value: Any = None
    expected_value: Any = None
    operator: str = "EQUALS"
    status: FindingStatus = "UNKNOWN"


class Finding(BaseModel):
    finding_id: str
    engine: str = "compliance"
    control_id: str
    title: str
    severity: Severity = "MEDIUM"
    status: FindingStatus = "FAIL"
    asset_id: str = "ASSET-001"
    evidence: Evidence | Dict[str, Any] = Field(default_factory=dict)
    remediation: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = 1.0
    frameworks: Dict[str, Any] = Field(default_factory=dict)


class VendorMapping(BaseModel):
    vendor: str
    platform: str = "any"
    raw_command_pattern: str
    canonical_property: str
    canonical_value: Any = None
    confidence: float = 1.0
    source: str = "curated"
    status: Literal["approved", "pending", "rejected"] = "approved"


class AuditRequest(BaseModel):
    asset_id: str = "ASSET-001"
    vendor: str = "cisco"
    platform: str = "ios-xe"
    config_text: str = ""
    frameworks: List[str] = Field(default_factory=lambda: ["CIS", "NIST", "STIG", "ISO27001"])


class AuditResult(BaseModel):
    audit_id: str
    compliance_score: float
    total: int
    passed: int
    failed: int
    unknown: int
    by_framework: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    findings: List[Finding] = Field(default_factory=list)
    okf_version: str = "1.0.0"


class SoftwareComponent(BaseModel):
    """SBOM-style inventory entry (cve_okf §11)."""
    vendor: str
    product: str
    version: str = ""
    component_type: str = "operating_system"
    cpe: Optional[str] = None
    source: str = "config_regex"


class CveMatch(BaseModel):
    asset_id: str = "ASSET-001"
    cve_id: Optional[str] = None
    product: str = ""
    installed_version: str = ""
    status: Literal["VULNERABLE", "NOT_AFFECTED", "UNKNOWN"] = "UNKNOWN"
    matched_rule: Optional[Dict[str, Any]] = None
    fixed_version: Optional[str] = None
    cvss: Dict[str, Any] = Field(default_factory=dict)
    cpe: str = ""
    confidence: Dict[str, float] = Field(default_factory=dict)


class CbomEntry(BaseModel):
    """Cryptographic Bill of Materials row (cve_okf §12, arch §17)."""
    asset_id: str = "ASSET-001"
    protocol: str = ""
    algorithm: str = ""
    key_size: Optional[int] = None
    usage: str = ""
    location: str = ""
    klass: str = "classical"
    pqc_status: str = "unknown"
