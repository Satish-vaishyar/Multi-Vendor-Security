"""Import a control catalogue (DISA STIG XCCDF, or CSV / JSON exported from a licensed benchmark) into the OKF.

Why this exists: the product ships a curated control subset, not the full CIS / DISA STIG / ISO 27001 texts (licensed or
restricted, and they must not be redistributed). A customer who holds the licence imports THEIR copy here:

  * every catalogue entry becomes a control, so the framework's real size is visible in the coverage figures;
  * an entry without a machine-checkable condition evaluates to UNKNOWN ("could not be assessed") - never PASS;
  * an optional mapping file (control id -> condition on canonical properties) switches individual entries to
    automated checks as they are authored and reviewed.

The output file is written to ``okf/knowledge/controls/imported_<framework>.yaml``; that pattern is git-ignored because it
may contain licensed text. A ``license`` and ``source`` are mandatory so provenance is never lost.
"""
from __future__ import annotations
import csv
import io
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from app.core import config as cfg

UNMAPPED_PROPERTY = "CATALOGUE.NOT_AUTOMATED"     # never present in a parsed config -> UNKNOWN, never PASS
_SEV = {"CAT I": "HIGH", "HIGH": "HIGH", "CAT II": "MEDIUM", "MEDIUM": "MEDIUM", "CAT III": "LOW", "LOW": "LOW",
        "CRITICAL": "CRITICAL", "INFO": "LOW", "INFORMATIONAL": "LOW"}
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,63}$")
MAX_BYTES = 50 * 1024 * 1024


class CatalogueError(ValueError):
    pass


def _sev(raw: str) -> str:
    return _SEV.get(str(raw or "").strip().upper(), "MEDIUM")


def parse_xccdf(data: bytes) -> List[Dict[str, Any]]:
    """DISA STIG XCCDF (the STIG Viewer / public.cyber.mil format)."""
    if len(data) > MAX_BYTES:
        raise CatalogueError("file too large")
    if re.search(rb"<!(DOCTYPE|ENTITY)", data, re.I):
        raise CatalogueError("DTD / entity declarations are not allowed in an XCCDF file")
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, DefusedXmlException) as e:
        raise CatalogueError(f"not valid or unsafe XML: {type(e).__name__}")
    out: List[Dict[str, Any]] = []
    for el in root.iter():
        if not el.tag.endswith("}Rule") and el.tag != "Rule":
            continue
        rid = el.get("id") or ""
        sev = el.get("severity") or ""
        def txt(name: str) -> str:
            for ch in el:
                if ch.tag.split("}")[-1] == name:
                    return "".join(ch.itertext()).strip()
            return ""
        ident = ""
        for ch in el:
            if ch.tag.split("}")[-1] == "version":
                ident = (ch.text or "").strip()
        out.append({"id": ident or rid, "title": txt("title"), "description": txt("description")[:2000],
                    "severity": _sev({"high": "CAT I", "medium": "CAT II", "low": "CAT III"}.get(sev.lower(), sev)),
                    "ref": rid})
    if not out:
        raise CatalogueError("no <Rule> elements found")
    return out


def parse_csv(data: bytes) -> List[Dict[str, Any]]:
    """Columns (case-insensitive): id, title, [description], [severity], [category]."""
    if len(data) > MAX_BYTES:
        raise CatalogueError("file too large")
    rd = csv.DictReader(io.StringIO(data.decode("utf-8-sig", errors="replace")))
    rows = []
    for r in rd:
        low = {str(k or "").strip().lower(): (v or "").strip() for k, v in r.items()}
        if not low.get("id") or not low.get("title"):
            continue
        rows.append({"id": low["id"], "title": low["title"], "description": low.get("description", "")[:2000],
                     "severity": _sev(low.get("severity", "")), "category": low.get("category", "general") or "general"})
    if not rows:
        raise CatalogueError("no rows with both 'id' and 'title' columns")
    return rows


def parse_json(data: bytes) -> List[Dict[str, Any]]:
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except ValueError as e:
        raise CatalogueError(f"not valid JSON: {e}")
    items = doc.get("controls") if isinstance(doc, dict) else doc
    if not isinstance(items, list):
        raise CatalogueError("expected a list of controls (or {\"controls\": [...]})")
    rows = [{"id": str(i.get("id") or i.get("control_id") or "").strip(), "title": str(i.get("title") or "").strip(),
             "description": str(i.get("description") or "")[:2000], "severity": _sev(i.get("severity", "")),
             "category": str(i.get("category") or "general")} for i in items if isinstance(i, dict)]
    rows = [r for r in rows if r["id"] and r["title"]]
    if not rows:
        raise CatalogueError("no entries with an id and a title")
    return rows


def detect_format(name: str, data: bytes) -> str:
    n = name.lower()
    if n.endswith((".xml", ".xccdf")) or data.lstrip()[:5] == b"<?xml":
        return "xccdf"
    if n.endswith(".json"):
        return "json"
    return "csv"


def build(framework: str, entries: List[Dict[str, Any]], *, license_: str, source: str,
          mapping: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    fw = re.sub(r"[^A-Za-z0-9_-]", "", framework).upper()
    if not fw:
        raise CatalogueError("framework name is required")
    if not license_.strip() or not source.strip():
        raise CatalogueError("license and source are required so the provenance of imported text is never lost")
    mapping = mapping or {}
    seen, controls, automated = set(), [], 0
    for e in entries:
        if not _ID.match(e["id"]):
            raise CatalogueError(f"unsafe or empty control id {e['id']!r}")
        cid = f"{fw}-{e['id']}"
        if cid in seen:
            raise CatalogueError(f"duplicate control id {e['id']!r}")
        seen.add(cid)
        m = mapping.get(e["id"]) or mapping.get(cid) or {}
        cond = m.get("condition")
        if cond:
            automated += 1
        controls.append({
            "control_id": cid, "title": e["title"][:300], "description": e.get("description", ""),
            "category": e.get("category", "general"), "severity": m.get("severity") or e["severity"], "version": "imported",
            "frameworks": {fw: e["id"]}, "evidence_type": "CONFIGURATION",
            "condition": cond or {"property": UNMAPPED_PROPERTY, "operator": "EQUALS", "value": True},
            **({"applies_to": m["applies_to"]} if m.get("applies_to") else {}),
            "references": [f"license: {license_.strip()}", f"source: {source.strip()}"]})
    return {"controls": controls, "_meta": {"framework": fw, "total": len(controls), "automated": automated}}


def write(doc: Dict[str, Any], directory: Optional[Path] = None) -> Path:
    meta = doc["_meta"]
    d = directory or (cfg.OKF_DIR / "knowledge" / "controls")
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"imported_{meta['framework'].lower()}.yaml"
    body = {"controls": doc["controls"]}
    path.write_text("# Imported catalogue - may contain licensed text; git-ignored. See docs/CATALOGUES.md.\n"
                    + yaml.safe_dump(body, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


def coverage(directory: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Per imported framework: total entries vs entries that have an automated check."""
    d = directory or (cfg.OKF_DIR / "knowledge" / "controls")
    out = []
    for f in sorted(d.glob("imported_*.yaml")):
        items = (yaml.safe_load(f.read_text(encoding="utf-8")) or {}).get("controls", [])
        auto = sum(1 for c in items if (c.get("condition") or {}).get("property") != UNMAPPED_PROPERTY)
        out.append({"file": f.name, "total": len(items), "automated": auto,
                    "automated_pct": round(100.0 * auto / len(items), 1) if items else 0.0})
    return out
