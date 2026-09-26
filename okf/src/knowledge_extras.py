"""Remediation KB, Risk engine, Mapping registry, Versioning (OKF components 7-9 + §33)."""
from __future__ import annotations
from pathlib import Path
import re
from typing import Any, Dict, List
import yaml
from .schemas import Finding, VendorMapping

KB = Path(__file__).parent.parent / "knowledge"
SEV_W = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0.5}


class RemediationKB:
    def __init__(self) -> None:
        self.index: Dict[str, Dict[str, Any]] = {}  # control_id -> {generic, vendors:{...}}

    def load(self, base: Path = KB / "remediation") -> "RemediationKB":
        self.index.clear()
        for f in sorted(Path(base).rglob("*.yaml")):
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            vendor = f.parent.name
            for item in data.get("remediations", []):
                cid = item["control_id"]
                entry = self.index.setdefault(cid, {"control_id": cid, "vendors": {}})
                entry["vendors"][vendor] = item
                entry.setdefault("title", item.get("title", ""))
        return self


class RiskEngine:
    """Deterministic: risk = severity × exposure × criticality × confidence (docs §15)."""

    @staticmethod
    def score_finding(f: Finding, asset_criticality: str = "HIGH",
                      internet_exposed: bool = False) -> Dict[str, Any]:
        sev = SEV_W.get(f.severity, 1)
        crit = {"CRITICAL": 1.5, "HIGH": 1.25, "MEDIUM": 1.0, "LOW": 0.8}.get(asset_criticality.upper(), 1.0)
        expo = 1.4 if internet_exposed else 1.0
        risk = round(min(10.0, sev * 2.0 * crit * expo * max(0.5, f.confidence)), 1)
        priority = "CRITICAL" if risk >= 8 else ("HIGH" if risk >= 6 else ("MEDIUM" if risk >= 3 else "LOW"))
        return {"risk_score": risk, "priority": priority,
                "factors": {"severity": f.severity, "asset_criticality": asset_criticality,
                            "internet_exposed": internet_exposed, "confidence": f.confidence}}


class MappingRegistry:
    """Vendor syntax -> canonical property. Deterministic regexes win; LLM fills gaps."""

    def __init__(self) -> None:
        self.maps: List[VendorMapping] = []

    def load(self, base: Path = KB / "mappings") -> "MappingRegistry":
        self.maps.clear()
        for f in sorted(Path(base).glob("*.yaml")):
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            for item in data.get("mappings", []):
                self.maps.append(VendorMapping(**item))
        learned = Path(base) / "learned"
        if learned.exists():
            for f in sorted(learned.glob("*.yaml")):
                data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
                for item in data.get("mappings", []):
                    self.maps.append(VendorMapping(**item))
        return self

    def to_canonical_ir(self, config_text: str, vendor: str = "cisco") -> Dict[str, Any]:
        """Apply deterministic mappings line-by-line -> flat IR dict."""
        ir: Dict[str, Any] = {}
        provenance: Dict[str, Dict[str, Any]] = {}
        for lineno, line in enumerate(config_text.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith(("!", "#")):
                continue
            for m in self.maps:
                if m.vendor not in ("any", vendor.lower()):
                    continue
                try:
                    if re.search(m.raw_command_pattern, s, re.IGNORECASE):
                        ir[m.canonical_property] = m.canonical_value
                        provenance[m.canonical_property] = {
                            "line": s, "line_no": lineno, "source": m.source,
                            "confidence": m.confidence}
                        break
                except re.error:
                    continue
        return {"ir": ir, "provenance": provenance}

    def approve(self, vendor: str, platform: str, pattern: str, prop: str,
                value: Any, out: Path | None = None) -> VendorMapping:
        m = VendorMapping(vendor=vendor, platform=platform, raw_command_pattern=pattern,
                          canonical_property=prop, canonical_value=value,
                          source="human_verified", status="approved")
        self.maps.append(m)
        dest = out or (KB / "mappings" / "learned" / f"{vendor.lower()}_learned.yaml")
        dest.parent.mkdir(parents=True, exist_ok=True)
        existing: List[Dict[str, Any]] = []
        if dest.exists():
            existing = (yaml.safe_load(dest.read_text(encoding="utf-8")) or {}).get("mappings", [])
        existing.append(m.model_dump())
        dest.write_text(yaml.safe_dump({"mappings": existing}, sort_keys=False), encoding="utf-8")
        return m


def nest_flat_ir(flat: Dict[str, Any]) -> Dict[str, Any]:
    """TELNET.ENABLED -> {"TELNET": {"ENABLED": ...}} for engine consumption."""
    nested: Dict[str, Any] = {}
    for k, v in flat.items():
        parts = k.split(".")
        cur = nested
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = v
    return nested
