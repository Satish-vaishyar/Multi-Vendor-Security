"""Context-aware remediation composer.

Fix templates live per vendor/property in ``knowledge/remediation/fixes/*.yaml``. For a failed control
this module works out *which parts of the control's condition are actually unmet* from the audit's own
canonical IR, picks the least disruptive alternative where the control accepts several (ANY), expands
per-object fixes with the real objects found in the configuration (the exact interface, vty range,
SNMP community, firewall policy ...), merges and de-duplicates, and returns an ordered plan with impact,
prerequisites, rollback and the parameters an operator must still supply.

Every plan states its verification level. Templates are written from vendor documentation; unless a file
says ``verification: lab-verified`` the plan is labelled **documented, not lab-verified**.
"""
from __future__ import annotations
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .engines import eval_op, _get  # noqa: F401  (shared operator semantics)

FIX_DIR = Path(__file__).parent.parent / "knowledge" / "remediation" / "fixes"
_DISRUPTION = {"low": 0, "medium": 1, "high": 2}
_PARAM_RE = re.compile(r"<([A-Z][A-Z0-9_]{1,40})>")
_FMT_RE = re.compile(r"\{(\w+)\}")

# platform token -> fix file stem (a platform with no file gets NO plan rather than wrong syntax)
PLATFORM_FILE = {
    ("cisco", "ios"): "cisco", ("cisco", "ios-xe"): "cisco",
    ("arista", "eos"): "arista", ("juniper", "junos"): "juniper",
    ("fortinet", "fortios"): "fortinet", ("paloalto", "pan-os"): "paloalto",
}


class FixLibrary:
    def __init__(self, base: Path = FIX_DIR):
        self.files: Dict[str, Dict[str, Any]] = {}
        for f in sorted(Path(base).glob("*.yaml")):
            self.files[f.stem] = yaml.safe_load(f.read_text(encoding="utf-8")) or {}

    # ------------------------------------------------------------------ lookup
    def library_for(self, vendor: str, platform: str) -> Optional[Dict[str, Any]]:
        stem = PLATFORM_FILE.get((vendor.lower(), (platform or "").lower()))
        if stem is None and vendor.lower() in ("cisco", "arista", "juniper", "fortinet", "paloalto") and not platform:
            stem = {"cisco": "cisco", "arista": "arista", "juniper": "juniper",
                    "fortinet": "fortinet", "paloalto": "paloalto"}[vendor.lower()]
        return self.files.get(stem) if stem else None

    def properties(self, vendor: str, platform: str) -> List[str]:
        lib = self.library_for(vendor, platform)
        return sorted((lib or {}).get("fixes", {}))

    # --------------------------------------------------------------- condition
    @staticmethod
    def unmet(cond: Dict[str, Any], ir: Dict[str, Any]) -> List[List[Dict[str, Any]]]:
        """Groups of leaves that must change. A group with several leaves = alternatives (ANY)."""
        if "all" in cond:
            out: List[List[Dict[str, Any]]] = []
            for c in cond["all"]:
                out += FixLibrary.unmet(c, ir)
            return out
        if "any" in cond:
            groups = [FixLibrary.unmet(c, ir) for c in cond["any"]]
            if any(not g for g in groups):          # one alternative already satisfied
                return []
            return [[leaf for g in groups for grp in g for leaf in grp]]
        ok = eval_op(_get(ir, cond.get("property", "")), cond.get("operator", "EQUALS"), cond.get("value"))
        return [] if ok else [[cond]]

    # ------------------------------------------------------------------- plan
    def plan(self, control: Any, ir: Dict[str, Any], provenance: Dict[str, Dict[str, Any]],
             vendor: str, platform: str = "") -> Optional[Dict[str, Any]]:
        lib = self.library_for(vendor, platform)
        if not lib:
            return None
        fixes = lib.get("fixes", {})
        groups = self.unmet(control.condition or {}, ir)
        if not groups:                                    # nothing unmet per the IR (e.g. N/A) -> no plan
            return None
        chosen: List[Tuple[str, Dict[str, Any]]] = []
        manual: List[str] = []
        for grp in groups:
            options = [(leaf["property"], fixes[leaf["property"]]) for leaf in grp
                       if leaf.get("property") in fixes and self._desired_matches(fixes[leaf["property"]], leaf)]
            if not options:
                manual.append(", ".join(sorted({l.get("property", "?") for l in grp})))
                continue
            options.sort(key=lambda po: _DISRUPTION.get(str(po[1].get("disruption", "medium")), 1))
            chosen.append(options[0])
        if not chosen:
            return None
        sections, seen_props = [], set()
        for prop, fix in chosen:
            self._expand(prop, fix, fixes, provenance, sections, seen_props)
        steps: List[Dict[str, Any]] = []
        seen_cmds: set = set()
        structural = {"exit", "end", "next", "quit"}
        for sec in sections:
            for cmd in sec["steps"]:
                bare = cmd.strip()
                if bare in seen_cmds and bare.split(" ")[0] not in structural and not bare.startswith(("!", "#")):
                    continue                       # same command already emitted by an earlier section
                seen_cmds.add(bare)
                steps.append({"order": len(steps) + 1, "command": cmd, "section": sec["property"]})
        text_blob = "\n".join(s["command"] for s in steps)
        params = sorted(set(_PARAM_RE.findall(text_blob)))
        descr = lib.get("parameters", {}) or {}
        return {
            "source": "fix-library", "vendor": lib.get("vendor"), "platform": platform,
            "verification": lib.get("verification", "documented"),
            "verification_note": ("Written from vendor documentation; not tested on a lab device. "
                                  "Review in a maintenance window and keep the rollback ready."
                                  if lib.get("verification", "documented") != "lab-verified"
                                  else "Validated on a lab device."),
            "sources": lib.get("sources", []),
            "apply_notes": lib.get("apply_notes", ""),
            "title": " + ".join(dict.fromkeys(s["title"] for s in sections if s.get("title"))) or control.title,
            "steps": steps,
            "sections": [{"property": s["property"], "title": s["title"], "impact": s.get("impact", ""),
                          "prerequisites": s.get("prerequisites", [])} for s in sections],
            "validation": list(dict.fromkeys(v for s in sections for v in s.get("validation", []))),
            "rollback": list(dict.fromkeys(r for s in reversed(sections) for r in s.get("rollback", []))),
            "impact": " ".join(dict.fromkeys(s["impact"] for s in sections if s.get("impact"))),
            "prerequisites": list(dict.fromkeys(p for s in sections for p in s.get("prerequisites", []))),
            "parameters": [{"name": p, "description": descr.get(p) or self._describe(p)} for p in params],
            "manual_review": manual,
            "approval_required": any(s.get("approval_required", True) for s in sections),
            "manual_steps": [s["property"] for s in sections if s.get("manual")],
        }

    @staticmethod
    def _describe(name: str) -> str:
        m = re.match(r"COMMUNITY_L(\d+)$", name)
        if m:      # communities are secrets: the plan points at the config line instead of storing the value
            return f"the SNMP community string configured at line {m.group(1)} of the uploaded configuration"
        return "value specific to your environment"

    @staticmethod
    def _desired_matches(fix: Dict[str, Any], leaf: Dict[str, Any]) -> bool:
        if "value" not in fix:
            return True
        return str(fix["value"]).lower() == str(leaf.get("value")).lower() or leaf.get("operator", "EQUALS") in ("GTE", "GT")

    def _expand(self, prop: str, fix: Dict[str, Any], fixes: Dict[str, Any], provenance: Dict[str, Dict[str, Any]],
                sections: List[Dict[str, Any]], seen: set) -> None:
        if prop in seen:
            return
        seen.add(prop)
        for inc in fix.get("includes", []) or []:
            if inc in fixes:
                self._expand(inc, fixes[inc], fixes, provenance, sections, seen)
        targets = list((provenance.get(prop) or {}).get("targets") or [])
        per_target = bool(fix.get("per_target"))
        if per_target and not targets:
            targets = [] if fix.get("skip_if_no_targets") else [{"name": fix.get("target_placeholder", "<TARGET>")}]
        cmds: List[str] = list(fix.get("setup", []) or [])
        rollback: List[str] = []
        if per_target:
            for t in targets:
                cmds += [self._fmt(c, t) for c in fix.get("commands", []) or []]
                rollback += [self._fmt(r, t) for r in fix.get("rollback", []) or []]
        else:
            cmds += list(fix.get("commands", []) or [])
            rollback = list(fix.get("rollback", []) or [])
        if not cmds and not fix.get("includes"):
            return
        if not cmds:                                   # pure "includes" wrapper: its children carry the steps
            return
        sections.append({"property": prop, "title": fix.get("title", prop), "steps": cmds,
                         "validation": [self._fmt(v, targets[0]) if (per_target and targets) else v
                                        for v in fix.get("validation", []) or []],
                         "rollback": rollback, "impact": fix.get("impact", ""),
                         "prerequisites": fix.get("prerequisites", []) or [],
                         "approval_required": fix.get("approval_required", True),
                         "manual": bool(fix.get("manual"))})

    @staticmethod
    def _fmt(template: str, target: Dict[str, Any]) -> str:
        return _FMT_RE.sub(lambda m: str(target.get(m.group(1), f"<{m.group(1).upper()}>")), template)

    # --------------------------------------------------------------- coverage
    def coverage(self, controls: List[Any], vendor: str, platform: str = "") -> Dict[str, Any]:
        """How many controls could get a plan if they failed (every unmet leaf group has a fix)."""
        lib = self.library_for(vendor, platform)
        if not lib:
            return {"controls": len(controls), "fixable": 0, "missing_properties": []}
        fixes = lib.get("fixes", {})
        fixable, missing = 0, set()
        for c in controls:
            leaves = []
            def walk(cond):
                if "all" in cond or "any" in cond:
                    for x in cond.get("all", []) + cond.get("any", []):
                        walk(x)
                elif cond.get("property"):
                    leaves.append(cond["property"])
            walk(c.condition or {})
            if leaves and any(p in fixes for p in leaves):
                fixable += 1
            else:
                missing.update(leaves)
        return {"controls": len(controls), "fixable": fixable, "missing_properties": sorted(missing)}
