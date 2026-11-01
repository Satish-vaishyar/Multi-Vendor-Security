"""Knowledge pack loader and validator (RTM S12; CM-081, CM-084).

Loads okf-cloud/knowledge/{properties,mappings,controls}/*.yaml. Validation is strict on purpose (it also runs in CI):
a pack with a dangling property, an unknown operator or an unverified benchmark ID cannot load.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import yaml

from cloud.ir import SEVERITIES

OPERATORS = ("EQUALS", "NOT_EQUALS", "GTE", "LTE", "GT", "LT", "IN", "NOT_IN", "CONTAINS", "EXISTS")
UNVERIFIABLE_FRAMEWORKS = ("CIS",)          # licensed benchmark IDs may only be published once verified against the edition
PROPERTY_TYPES = ("boolean", "string", "integer")


class PackError(ValueError):
    """The knowledge pack is invalid; the message lists every problem found."""


@dataclass
class Control:
    id: str
    name: str
    severity: str
    category: str
    condition: Dict[str, Any]
    logic_version: str
    frameworks: List[Dict[str, Any]]
    remediation: Dict[str, Any]
    unknown_handling: str = ""
    references: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class Pack:
    version: str
    properties: Dict[str, Dict[str, Any]]
    mappings: List[Dict[str, Any]]
    controls: List[Control]
    by_type: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    customisations: List[str] = field(default_factory=list)      # organisation changes to the built-in pack, always reported


def default_pack_dir() -> Path:
    """CLOUD_OKF_DIR, else <repo>/okf-cloud (the same relative layout in the container: /srv/cloud and /srv/okf-cloud)."""
    env = os.environ.get("CLOUD_OKF_DIR")
    return Path(env) if env else Path(__file__).resolve().parents[2] / "okf-cloud"


def _load_dir(base: Path, key: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    folder = base / "knowledge" / key
    for f in sorted(folder.glob("*.yaml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        items.extend(doc.get(key) or [])
    return items


def condition_properties(cond: Dict[str, Any]) -> List[str]:
    if "all" in cond or "any" in cond:
        return [p for c in cond.get("all", []) + cond.get("any", []) for p in condition_properties(c)]
    return [cond["property"]] if cond.get("property") else []


def _check_condition(cond: Any, props: Dict[str, Any], where: str, errors: List[str]) -> None:
    if not isinstance(cond, dict):
        errors.append(f"{where}: condition must be a mapping")
        return
    if "all" in cond or "any" in cond:
        for c in cond.get("all", []) + cond.get("any", []):
            _check_condition(c, props, where, errors)
        return
    if cond.get("property") not in props:
        errors.append(f"{where}: unknown property {cond.get('property')!r}")
    if str(cond.get("operator", "EQUALS")).upper() not in OPERATORS:
        errors.append(f"{where}: unknown operator {cond.get('operator')!r}")


def load_pack(base: Path | None = None) -> Pack:
    """Load and validate the pack. Raises PackError listing every problem."""
    base = base or default_pack_dir()
    errors: List[str] = []
    manifest = yaml.safe_load((base / "okf_manifest.yaml").read_text(encoding="utf-8")) or {}
    props: Dict[str, Dict[str, Any]] = {}
    for p in _load_dir(base, "properties"):
        pid = p.get("id")
        if not pid or pid in props:
            errors.append(f"property {pid!r}: missing or duplicate id")
            continue
        if p.get("type") not in PROPERTY_TYPES:
            errors.append(f"property {pid}: type must be one of {PROPERTY_TYPES}")
        props[pid] = p

    from cloud.rules import extractors
    mappings = _load_dir(base, "mappings")
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for m in mappings:
        where = f"mapping {m.get('id')!r}"
        if not m.get("id") or not m.get("resource_types"):
            errors.append(f"{where}: id and resource_types are required")
            continue
        for pid in (m.get("properties") or {}):
            if pid not in props:
                errors.append(f"{where}: unknown property {pid!r}")
        for name in m.get("extractors") or []:
            if name not in extractors.REGISTRY:
                errors.append(f"{where}: unknown extractor {name!r}")
        for spec in (m.get("properties") or {}).values():
            if not isinstance(spec, dict) or not ({"paths", "all_true"} & set(spec)):
                errors.append(f"{where}: property spec needs paths or all_true")
            elif spec.get("op") and spec["op"] not in extractors.OPS:
                errors.append(f"{where}: unknown op {spec['op']!r}")
        for rtype in m["resource_types"]:
            by_type.setdefault(rtype, []).append(m)

    controls: List[Control] = []
    seen = set()
    for c in _load_dir(base, "controls"):
        cid = c.get("id", "")
        where = f"control {cid!r}"
        if not str(cid).startswith("CLOUD-") or cid in seen:
            errors.append(f"{where}: id must start with CLOUD- and be unique")
        seen.add(cid)
        if c.get("severity") not in SEVERITIES:
            errors.append(f"{where}: invalid severity {c.get('severity')!r}")
        for req in ("name", "category", "logic_version", "condition"):
            if not c.get(req):
                errors.append(f"{where}: {req} is required")
        if not (c.get("remediation") or {}).get("summary"):
            errors.append(f"{where}: remediation.summary is required")
        _check_condition(c.get("condition"), props, where, errors)
        fws = c.get("frameworks") or []
        for fw in fws:
            if not fw.get("framework") or not fw.get("control_id") or not isinstance(fw.get("verified"), bool):
                errors.append(f"{where}: each framework mapping needs framework, control_id and a boolean 'verified'")
            elif fw["framework"] in UNVERIFIABLE_FRAMEWORKS and not fw["verified"]:
                errors.append(f"{where}: {fw['framework']} IDs may only be published when verified against the licensed edition")
        controls.append(Control(
            id=cid, name=c.get("name", ""), severity=c.get("severity", ""), category=c.get("category", ""),
            condition=c.get("condition") or {}, logic_version=str(c.get("logic_version", "")), frameworks=fws,
            remediation=c.get("remediation") or {}, unknown_handling=c.get("unknown_handling", ""),
            references=c.get("references") or [], description=c.get("description", "")))
    if errors:
        raise PackError("; ".join(errors))
    return Pack(version=str(manifest.get("okf_cloud_version", "0")), properties=props, mappings=mappings,
                controls=controls, by_type=by_type)
