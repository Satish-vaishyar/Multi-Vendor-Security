"""Knowledge Learning Engine (OKF component 10): unknown detection + mapping + LLM parser.

ALL LLM calls go through llm_gateway (single-file rule). Deterministic wins.

Evidence precedence, strongest first:
  1. human-verified registry mappings (an operator explicitly decided what a line means)
  2. structured vendor parser facts (context-aware: blocks, negation, defaults)  -> src/vendor_parsers
  3. curated regex mappings from the registry (gap-fill for lines the parser has no rule for)
  4. LLM / heuristic suggestions (never overrides anything above)
"""
from __future__ import annotations
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).parent.parent))
from llm_gateway import parse_config_to_ir, suggest_mapping  # noqa: E402
from .knowledge_extras import MappingRegistry, nest_flat_ir  # noqa: E402
from . import vendor_parsers  # noqa: E402


class LearningEngine:
    def __init__(self, registry: MappingRegistry):
        self.registry = registry

    def audit_config(self, config_text: str, vendor: str = "cisco", platform: str = "") -> Dict[str, Any]:
        det = self.registry.to_canonical_ir(config_text, vendor=vendor)
        flat: Dict[str, Any] = dict(det["ir"])
        prov: Dict[str, Dict[str, Any]] = dict(det["provenance"])

        structured = vendor_parsers.parse(config_text, vendor, platform)
        consumed = set()
        parser_info: Dict[str, Any] = {"used": False}
        not_applicable: Dict[str, str] = {}
        if structured is not None:
            not_applicable = {p: why for p, why in structured.not_applicable.items() if p not in flat}
            consumed = set(structured.consumed)
            for prop, value in structured.flat.items():
                if prop in flat and prov.get(prop, {}).get("source") == "human_verified":
                    continue                      # explicit human decision outranks the parser
                flat[prop] = value
                prov[prop] = structured.provenance[prop]
            observed = sum(1 for p in structured.provenance.values() if p.get("basis") == "config")
            parser_info = {"used": True, "vendor": structured.vendor, "platform": structured.platform,
                           "properties": len(structured.flat), "observed": observed,
                           "assumed_defaults": len(structured.flat) - observed, "notes": structured.notes}

        # lines still unexplained: not consumed by the parser, not matched by a registry rule
        registry_lines = {v.get("line") for v in det["provenance"].values()}
        uncovered_lines: List[str] = []
        for no, line in enumerate(config_text.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith(("!", "#")):
                continue
            if no in consumed or s in registry_lines:
                continue
            uncovered_lines.append(s)

        llm = parse_config_to_ir("\n".join(uncovered_lines), vendor=vendor) if uncovered_lines else {"mappings": []}
        for m in llm.get("mappings", []):
            if m["canonical_property"] not in flat:       # deterministic wins
                flat[m["canonical_property"]] = m["canonical_value"]
        llm_lines = {m.get("evidence", "") for m in llm.get("mappings", [])}
        unknowns = [l for l in uncovered_lines if l not in llm_lines]
        return {"flat_ir": flat, "nested_ir": nest_flat_ir(flat),
                "provenance": prov, "llm": llm, "parser": parser_info, "not_applicable": not_applicable,
                "unknown_lines": unknowns, "offline": llm.get("offline", True)}

    def suggest(self, raw_command: str, vendor: str = "unknown",
                context: List[str] | None = None) -> Dict[str, Any]:
        return suggest_mapping(raw_command, vendor, context)

    def approve(self, vendor: str, platform: str, pattern: str,
                prop: str, value: Any) -> Any:
        return self.registry.approve(vendor, platform, pattern, prop, value)
