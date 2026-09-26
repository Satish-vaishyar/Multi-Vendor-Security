"""Canonical Property Registry — loads knowledge/properties/*.yaml (OKF component 1)."""
from __future__ import annotations
from pathlib import Path
from typing import Dict, List
import yaml
from .schemas import CanonicalProperty

BASE = Path(__file__).parent.parent / "knowledge" / "properties"


class PropertyRegistry:
    def __init__(self) -> None:
        self.props: Dict[str, CanonicalProperty] = {}

    def load(self, base: Path = BASE) -> "PropertyRegistry":
        self.props.clear()
        for f in sorted(Path(base).glob("*.yaml")):
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            for item in data.get("properties", []):
                p = CanonicalProperty(**item)
                self.props[p.property_id] = p
        return self

    def get(self, pid: str) -> CanonicalProperty | None:
        return self.props.get(pid)

    def all(self) -> List[CanonicalProperty]:
        return list(self.props.values())

    def ids(self) -> List[str]:
        return sorted(self.props.keys())
