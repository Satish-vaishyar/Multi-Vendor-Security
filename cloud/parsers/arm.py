"""Azure Resource Manager template parser (RTM S15; CM-054).

Static and offline. Template expressions (`[...]`) are resolved only for `parameters('x')` / `variables('x')` that have a
literal default or value in the template itself; everything else is `Unknown`. Nested resources are flattened with their
full type. Bicep is NOT compiled here (it needs a pinned compiler in the sandbox image); a Bicep upload is reported as an
unsupported format, never as clean.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from cloud import secret_scan
from cloud.ir import Resource, Source, Unknown
from cloud.parsers.terraform import ParseResult

_PARSER = "cloud.parsers.arm 1"
_LOOKUP = re.compile(r"^\[\s*(parameters|variables)\(\s*'([^']+)'\s*\)\s*\]$")
MAX_DEPTH = 40
MAX_RESOURCES = 5000
MAX_NESTING = 10
MAX_TEXT = 512


def _value(v: Any, ctx: Dict[str, Dict[str, Any]], depth: int = 0) -> Any:
    if depth > MAX_DEPTH:
        return Unknown("nesting too deep")
    if isinstance(v, str):
        if v.startswith("[[") :
            return v[1:]
        if v.startswith("[") and v.endswith("]"):
            m = _LOOKUP.match(v)
            if m and m.group(2) in ctx[m.group(1)]:
                return ctx[m.group(1)][m.group(2)]
            return Unknown("template expression is not resolvable offline", v[:200])
        return v
    if isinstance(v, dict):
        return {k: _value(x, ctx, depth + 1) for k, x in v.items()}
    if isinstance(v, list):
        return [_value(x, ctx, depth + 1) for x in v]
    return v


def _context(doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    params = {k: v["defaultValue"] for k, v in (doc.get("parameters") or {}).items()
              if isinstance(v, dict) and "defaultValue" in v and str(v.get("type", "")).lower() not in ("securestring", "secureobject") and not (isinstance(v["defaultValue"], str) and v["defaultValue"].startswith("[") and not v["defaultValue"].startswith("[["))}
    variables = {k: v for k, v in (doc.get("variables") or {}).items() if not (isinstance(v, str) and v.startswith("[") and not v.startswith("[["))}
    return {"parameters": params, "variables": variables}


def _line_of(text: str, rtype: str, cursor: int) -> tuple:
    i = text.find(json.dumps(rtype), cursor)
    if i < 0:
        i = text.find(rtype, cursor)
    if i < 0:
        return 1, cursor
    return text.count("\n", 0, i) + 1, i + 1


def parse_arm(path: str, text: str) -> ParseResult:
    result = ParseResult()
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError) as e:
        result.errors.append({"file": path, "error": f"invalid JSON: {str(e)[:200]}"})
        return result
    if not isinstance(doc, dict) or not isinstance(doc.get("resources"), (list, dict)):
        result.errors.append({"file": path, "error": "no resources array in the ARM template"})
        return result
    ctx = _context(doc)
    seen: Dict[str, int] = {}
    cursor = [0]
    ctx["parameters"].update({k: Unknown("secure parameter: its value is never read")
                              for k, v in (doc.get("parameters") or {}).items()
                              if isinstance(v, dict) and str(v.get("type", "")).lower() in ("securestring", "secureobject")})

    def emit(item: Any, parent_type: str, parent_name: str, depth: int = 0) -> None:
        if not isinstance(item, dict) or len(result.resources) >= MAX_RESOURCES or depth > MAX_NESTING:
            result.truncated = result.truncated or len(result.resources) >= MAX_RESOURCES or depth > MAX_NESTING
            return
        rtype = item.get("type")
        if not isinstance(rtype, str) or not rtype:
            result.errors.append({"file": path, "error": "resource without a type"})
            return
        full = (f"{parent_type}/{rtype}" if parent_type else rtype)[:MAX_TEXT]
        name = _value(item.get("name"), ctx)
        name_s = secret_scan.redact(name)[:MAX_TEXT] if isinstance(name, str) else "(dynamic)"
        name_s = (f"{parent_name}/{name_s}" if parent_name else name_s)[:MAX_TEXT]
        line, cursor[0] = _line_of(text, rtype, cursor[0])
        addr = f"{full}/{name_s}"
        seen[addr] = seen.get(addr, 0) + 1
        if seen[addr] > 1:
            addr = f"{addr}#{seen[addr]}"
        props = {k: _value(v, ctx) for k, v in item.items() if k not in ("resources", "type", "name")}
        props["name"] = name
        notes = []
        if "copy" in item:
            notes.append("copy loop: instance count and names are not expanded offline")
        if "condition" in item:
            notes.append("deployed only when its condition holds; the condition was not evaluated")
        result.resources.append(Resource(
            provider="azure", service=full.split("/")[0], resource_type=full, logical_name=name_s.rsplit("/", 1)[-1], address=addr,
            properties=props, source=Source(path, line, line, "arm", _PARSER), notes=notes, provider_raw={}).finalize())
        for child in item.get("resources") or []:
            emit(child, full, name_s, depth + 1)

    top = doc["resources"]
    try:
        for item in (top.values() if isinstance(top, dict) else top):      # symbolic-name templates use an object
            emit(item, "", "")
    except RecursionError:
        result.errors.append({"file": path, "error": "template nesting too deep"})
        result.truncated = True
    return result
