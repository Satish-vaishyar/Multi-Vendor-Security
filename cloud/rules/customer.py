"""Customer rule packs and policy customisation (RTM S34; CM-143).

A private pack adds controls and adjusts severities WITHOUT code changes, under hard limits so it can never weaken the engine:
* it can only add controls whose ids start with CUSTOM- (it cannot replace or shadow a built-in control);
* conditions may reference only properties the built-in pack already defines (no new extractors, mappings or code);
* turning a built-in control off requires a written justification and is always reported in the scan coverage, never silent;
* every file and the total number of controls are bounded, and YAML is loaded with the safe loader.
Layout: <dir>/controls/*.yaml (key `controls:`) and an optional <dir>/policy.yaml with `severity:` and `disable:` mappings.
"""
from __future__ import annotations

import os
import re
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from cloud.ir import SEVERITIES
from cloud.rules.pack import Control, Pack, PackError, _check_condition, load_pack

ENV_VAR = "CLOUD_CUSTOMER_PACK_DIR"
MAX_FILE = 1024 * 1024
MAX_FILES = 50
MAX_CONTROLS = 200
_ID = re.compile(r"^CUSTOM-[A-Z0-9][A-Z0-9-]{0,39}$")
_CONTROL_KEYS = {"id", "name", "category", "severity", "condition", "logic_version", "frameworks", "remediation", "unknown_handling",
                 "references", "description", "assessment_mode"}


def _read(path: Path, errors: List[str]) -> Dict[str, Any]:
    try:
        if path.stat().st_size > MAX_FILE:
            errors.append(f"{path.name}: larger than {MAX_FILE} bytes")
            return {}
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        errors.append(f"{path.name}: unreadable ({type(e).__name__})")
        return {}
    if not isinstance(doc, dict):
        errors.append(f"{path.name}: must be a mapping")
        return {}
    return doc


def extend_pack(base: Pack, directory: Path) -> Pack:
    errors: List[str] = []
    files = sorted((directory / "controls").glob("*.yaml")) if (directory / "controls").is_dir() else []
    if len(files) > MAX_FILES:
        raise PackError(f"more than {MAX_FILES} control files")
    known = {c.id for c in base.controls}
    added: List[Control] = []
    for f in files:
        doc = _read(f, errors)
        extra = set(doc) - {"controls"}
        if extra:
            errors.append(f"{f.name}: only a 'controls' key is allowed (found {sorted(extra)}); customer packs cannot add code or mappings")
        for c in doc.get("controls") or []:
            if not isinstance(c, dict):
                errors.append(f"{f.name}: a control must be a mapping")
                continue
            cid = str(c.get("id", ""))
            where = f"control {cid!r}"
            if not _ID.match(cid) or cid in known:
                errors.append(f"{where}: id must match CUSTOM-<A-Z0-9-> and be unique")
            known.add(cid)
            bad = set(c) - _CONTROL_KEYS
            if bad:
                errors.append(f"{where}: unsupported keys {sorted(bad)}")
            if c.get("severity") not in SEVERITIES:
                errors.append(f"{where}: invalid severity {c.get('severity')!r}")
            for req in ("name", "category", "condition"):
                if not c.get(req):
                    errors.append(f"{where}: {req} is required")
            if not (c.get("remediation") or {}).get("summary"):
                errors.append(f"{where}: remediation.summary is required")
            _check_condition(c.get("condition"), base.properties, where, errors)
            for fw in c.get("frameworks") or []:
                if not isinstance(fw, dict) or not fw.get("framework") or not fw.get("control_id") or fw.get("verified") is not False:
                    errors.append(f"{where}: customer framework mappings need framework, control_id and verified: false")
            added.append(Control(
                id=cid, name=str(c.get("name", "")), severity=str(c.get("severity", "")), category=str(c.get("category", "")),
                condition=c.get("condition") or {}, logic_version=str(c.get("logic_version", "1")), frameworks=c.get("frameworks") or [],
                remediation=c.get("remediation") or {}, unknown_handling=str(c.get("unknown_handling", "")),
                references=c.get("references") or [], description=str(c.get("description", ""))))
    if len(added) > MAX_CONTROLS:
        errors.append(f"more than {MAX_CONTROLS} customer controls")

    notes: List[str] = [f"added {len(added)} customer control(s)"] if added else []
    controls = list(base.controls)
    policy_file = directory / "policy.yaml"
    policy = _read(policy_file, errors) if policy_file.exists() else {}
    builtin = {c.id for c in base.controls}
    for cid, sev in (policy.get("severity") or {}).items():
        if cid not in builtin or sev not in SEVERITIES:
            errors.append(f"policy severity {cid!r}: must name a built-in control and a valid severity")
        else:
            controls = [replace(c, severity=sev) if c.id == cid else c for c in controls]
            notes.append(f"severity of {cid} set to {sev} by the organisation")
    for cid, why in (policy.get("disable") or {}).items():
        if cid not in builtin:
            errors.append(f"policy disable {cid!r}: not a built-in control")
        elif len(str(why or "").strip()) < 20:
            errors.append(f"policy disable {cid!r}: a written justification of at least 20 characters is required")
        else:
            controls = [c for c in controls if c.id != cid]
            notes.append(f"{cid} disabled by the organisation: {str(why).strip()[:200]}")
    unknown_policy = set(policy) - {"severity", "disable"}
    if unknown_policy:
        errors.append(f"policy.yaml: unsupported keys {sorted(unknown_policy)}")
    if errors:
        raise PackError("; ".join(errors))
    return replace(base, version=f"{base.version}+customer" if notes else base.version, controls=controls + added,
                   customisations=notes)


def load_effective_pack(base: Optional[Pack] = None, env: Optional[Dict[str, str]] = None) -> Pack:
    """The built-in pack, extended with the directory named by CLOUD_CUSTOMER_PACK_DIR when that is set."""
    base = base or load_pack()
    directory = (os.environ if env is None else env).get(ENV_VAR, "").strip()
    return extend_pack(base, Path(directory)) if directory else base
