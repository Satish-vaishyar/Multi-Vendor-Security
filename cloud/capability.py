"""Capability matrix per provider and resource family, GENERATED from the knowledge pack and parser support (RTM S26; CM-041,
CM-141). Nothing here is hand-written marketing: a level is only reached when the pack really contains the evidence.

P0 identified   provider/format is recognised
P1 parsed       resource declarations are parsed with source locations
P2 normalised   the resource type is mapped to canonical properties
P3 security     at least one control evaluates that resource type
P4 compliance   every control that applies to it has framework mappings, ALL of them verified
P5 live         read-only live assessment (not implemented)
P6 graph/drift  relationship graph and static/live drift (not implemented)
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Set

from cloud.detect import _TF_PROVIDER
from cloud.rules import extractors
from cloud.rules.pack import Pack, condition_properties

# provider -> formats the parsers can read for it (kept next to the parsers they describe)
PARSED_FORMATS: Dict[str, List[str]] = {
    "aws": ["terraform_hcl", "terraform_json", "terraform_plan", "cloudformation"], "azure": ["terraform_hcl", "terraform_json", "terraform_plan"],
    "gcp": ["terraform_hcl", "terraform_json", "terraform_plan"], "oci": ["terraform_hcl", "terraform_json", "terraform_plan"],
    "kubernetes": ["kubernetes"]}
LEVELS = ("P0", "P1", "P2", "P3", "P4", "P5", "P6")


def provider_of_type(rtype: str) -> str:
    if rtype.startswith("AWS::"):
        return "aws"
    if rtype.startswith("Microsoft."):
        return "azure"
    if rtype[:1].isupper() and "::" not in rtype and "." not in rtype:
        return "kubernetes"
    return _TF_PROVIDER.get(rtype.split("_", 1)[0], rtype.split("_", 1)[0])


def _family(rtype: str) -> str:
    if rtype.startswith(("AWS::", "Microsoft.")):
        return rtype.split("::")[1].lower() if "::" in rtype else rtype.split("/")[0].split(".")[-1].lower()
    return rtype.split("_")[1] if "_" in rtype else "workload"


def build_matrix(pack: Pack) -> Dict[str, Any]:
    """{provider: {"level": "P3", "formats": [...], "families": {family: {"level": ..., "resource_types": [...], "controls": [...]}}}}"""
    declared: Dict[str, Set[str]] = {}
    for rtype, mappings in pack.by_type.items():
        props: Set[str] = set()
        for m in mappings:
            props |= set((m.get("properties") or {}))
            for name in m.get("extractors") or []:
                props |= set(extractors.extractor_properties(name, rtype))
        declared[rtype] = props
    out: Dict[str, Any] = defaultdict(lambda: {"families": {}})
    for rtype, props in sorted(declared.items()):
        provider = provider_of_type(rtype)
        controls = [c for c in pack.controls if condition_properties(c.condition) and set(condition_properties(c.condition)) <= props]
        verified = bool(controls) and all(fw.get("verified") for c in controls for fw in c.frameworks) and all(c.frameworks for c in controls)
        level = "P2" if not controls else ("P4" if verified else "P3")
        fam = out[provider]["families"].setdefault(_family(rtype), {"level": "P2", "resource_types": [], "controls": []})
        fam["resource_types"].append(rtype)
        fam["controls"] = sorted(set(fam["controls"]) | {c.id for c in controls})
        fam["level"] = max(fam["level"], level, key=LEVELS.index)
    for provider, entry in out.items():
        entry["formats"] = PARSED_FORMATS.get(provider, [])
        entry["level"] = max((f["level"] for f in entry["families"].values()), key=LEVELS.index)
        entry["not_implemented"] = ["P5 live assessment", "P6 relationship graph / drift"]
    return dict(out)
