"""Structured, context-aware vendor parsers (see base.py for the fact model)."""
from __future__ import annotations
from typing import Optional

from .base import ParseResult
from .fingerprint import fingerprint

__version__ = "1.0.0"
SUPPORTED = ("cisco", "arista", "juniper", "fortinet", "paloalto")


def parse(text: str, vendor: str, platform: str = "") -> Optional[ParseResult]:
    """Run the structured parser for ``vendor``; None when the vendor has no structured parser
    (the caller then falls back to the mapping registry + AI loop)."""
    v = (vendor or "").lower()
    if v in ("cisco", "arista"):
        from . import ioslike
        return ioslike.parse(text, v, platform)
    if v == "juniper":
        from . import junos
        return junos.parse(text, platform)
    if v == "fortinet":
        from . import fortios
        return fortios.parse(text, platform)
    if v == "paloalto":
        from . import panos
        return panos.parse(text, platform)
    return None


__all__ = ["parse", "fingerprint", "ParseResult", "SUPPORTED"]
