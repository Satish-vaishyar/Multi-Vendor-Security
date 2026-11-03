"""L3 Parsing (arch.md §6-7): deterministic vendor parsers win, AI fills gaps.

- Deterministic: OKF MappingRegistry regexes (cisco/juniper/fortinet/paloalto/arista).
- AI gap-fill: okf LearningEngine -> llm_gateway (Featherless gpt-oss-120b live,
  heuristic offline). Never overrides deterministic values.
- M5 validation: Canonical IR must use known property vocabulary.
"""
from __future__ import annotations
from typing import Any, Dict

from app.services.integration import learning_engine, okf_layer


def parse_to_canonical(config_text: str, vendor: str, platform: str = "") -> Dict[str, Any]:
    okf = okf_layer()
    result = learning_engine().audit_config(config_text, vendor=vendor.lower(), platform=(platform or "").lower())
    flat: Dict[str, Any] = dict(result.get("flat_ir", {}))
    # M5-style gate: drop anything outside the property registry vocabulary
    vocab = {p.property_id for p in okf["props"].all()}
    flat = {k: v for k, v in flat.items() if k in vocab}
    return {"flat_ir": flat,
            "nested_ir": okf["nest"](flat),
            "provenance": result.get("provenance", {}),
            "parser": result.get("parser", {}),
            "not_applicable": result.get("not_applicable", {}),
            "unknown_lines": result.get("unknown_lines", []),
            "llm_offline": result.get("offline", True),
            "llm": result.get("llm", {})}
