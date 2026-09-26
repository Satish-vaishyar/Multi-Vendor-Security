"""Control KB + Framework registry + Crosswalk (OKF components 2-4)."""
from __future__ import annotations
from pathlib import Path
import json
from typing import Dict, List
import yaml
from .schemas import Control, Framework, CrosswalkEntry

KB = Path(__file__).parent.parent / "knowledge"


class ControlKB:
    def __init__(self) -> None:
        self.controls: Dict[str, Control] = {}

    def load(self, base: Path = KB / "controls") -> "ControlKB":
        self.controls.clear()
        for f in sorted(Path(base).glob("*.yaml")):
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            for item in data.get("controls", []):
                c = Control(**item)
                self.controls[c.control_id] = c
        return self

    def all(self) -> List[Control]:
        return list(self.controls.values())

    def for_frameworks(self, frameworks: List[str]) -> List[Control]:
        fw = {f.upper() for f in frameworks}
        return [c for c in self.controls.values()
                if not fw or fw & {k.upper() for k in c.frameworks}]


class FrameworkRegistry:
    def __init__(self) -> None:
        self.frameworks: Dict[str, Framework] = {}

    def load(self, base: Path = KB / "frameworks") -> "FrameworkRegistry":
        self.frameworks.clear()
        for f in sorted(Path(base).glob("*.json")):
            try:
                payload = json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(payload, dict) or "framework_id" not in payload:
                continue  # scraped evidence files (*_SCRAPED.json, NIST_OSCAL.json)
            self.frameworks[f.stem.upper()] = Framework(**payload)
        return self


class Crosswalk:
    def __init__(self) -> None:
        self.entries: Dict[str, CrosswalkEntry] = {}

    def load(self, base: Path = KB / "crosswalks") -> "Crosswalk":
        self.entries.clear()
        for f in sorted(Path(base).glob("*.yaml")):
            data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            for item in data.get("crosswalk", []):
                e = CrosswalkEntry(**item)
                self.entries[e.canonical_property] = e
        return self

    def for_control(self, control_id: str, controls: Dict[str, Control]) -> Dict[str, List[Dict[str, str]]]:
        """control_id -> {framework: [mapped control ids]} via shared canonical property."""
        c = controls.get(control_id)
        if not c:
            return {"mapped_controls": []}
        out: List[Dict[str, str]] = []
        for fw, fid in c.frameworks.items():
            out.append({"framework": fw, "control_id": fid})
        return {"control_id": control_id, "mapped_controls": out}
