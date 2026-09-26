"""Knowledge Learning Engine (OKF component 10): unknown detection + mapping + LLM parser.

ALL LLM calls go through llm_gateway (single-file rule). Deterministic wins.
"""
from __future__ import annotations
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).parent.parent))
from llm_gateway import parse_config_to_ir, suggest_mapping  # noqa: E402
from .knowledge_extras import MappingRegistry, nest_flat_ir  # noqa: E402


class LearningEngine:
    def __init__(self, registry: MappingRegistry):
        self.registry = registry

    def audit_config(self, config_text: str, vendor: str = "cisco") -> Dict[str, Any]:
        det = self.registry.to_canonical_ir(config_text, vendor=vendor)
        covered = set(det["ir"].keys())
        uncovered_lines = []
        for line in config_text.splitlines():
            s = line.strip()
            if not s or s.startswith(("!", "#")):
                continue
            hit = any(s == v.get("line") for v in det["provenance"].values())
            if not hit:
                uncovered_lines.append(s)
        llm = parse_config_to_ir("\n".join(uncovered_lines), vendor=vendor) if uncovered_lines else {"mappings": []}
        merged_flat = dict(det["ir"])
        for m in llm.get("mappings", []):
            if m["canonical_property"] not in merged_flat:  # deterministic wins
                merged_flat[m["canonical_property"]] = m["canonical_value"]
        llm_lines = {m.get("evidence", "") for m in llm.get("mappings", [])}
        unknowns = [l for l in uncovered_lines if l not in llm_lines]
        return {"flat_ir": merged_flat, "nested_ir": nest_flat_ir(merged_flat),
                "provenance": det["provenance"], "llm": llm,
                "unknown_lines": unknowns, "offline": llm.get("offline", True)}

    def suggest(self, raw_command: str, vendor: str = "unknown",
                context: List[str] | None = None) -> Dict[str, Any]:
        return suggest_mapping(raw_command, vendor, context)

    def approve(self, vendor: str, platform: str, pattern: str,
                prop: str, value: Any):
        return self.registry.approve(vendor, platform, pattern, prop, value)
