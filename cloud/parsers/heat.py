"""OpenStack Heat (HOT) template parser (RTM S29; CM-055).

Static and offline. `get_param` resolves only to a literal parameter default; `get_resource` becomes a `Ref`; every other
intrinsic function (get_attr, str_replace, list_join, ...) is `Unknown`. Nothing is executed. Only resources whose type has a
rule are assessed; the others are carried in the IR so they appear in coverage, never as a clean result.
"""
from __future__ import annotations

from typing import Any, Dict

from cloud import yamlutil
from cloud.ir import Ref, Resource, Source, Unknown
from cloud.parsers.terraform import ParseResult

_PARSER = "cloud.parsers.heat 1"
MAX_DEPTH = 40
MAX_RESOURCES = 5000
_INTRINSICS = ("str_replace", "list_join", "digest", "repeat", "map_merge", "map_replace", "yaql", "if", "list_concat")


def _value(v: Any, params: Dict[str, Any], depth: int = 0) -> Any:
    if depth > MAX_DEPTH:
        return Unknown("nesting too deep")
    if isinstance(v, dict):
        if len(v) == 1:
            (fn, arg), = v.items()
            if fn == "get_param":
                name = arg[0] if isinstance(arg, list) and len(arg) == 1 else arg
                return params[name] if isinstance(name, str) and name in params else Unknown("parameter without a literal default")
            if fn == "get_resource":
                return Ref(arg) if isinstance(arg, str) else Unknown("computed resource reference")
            if isinstance(fn, str) and (fn.startswith("get_") or fn in _INTRINSICS):
                return Unknown(f"intrinsic function {fn} is not evaluated offline")
        return {str(k): _value(x, params, depth + 1) for k, x in v.items()}
    if isinstance(v, list):
        return [_value(x, params, depth + 1) for x in v]
    return v


def parse_heat(path: str, text: str) -> ParseResult:
    result = ParseResult()
    try:
        docs = yamlutil.load_all(text)
    except yamlutil.YamlError as e:
        result.errors.append({"file": path, "error": f"invalid YAML/JSON: {e}"[:200]})
        return result
    doc = docs[0] if docs else None
    if not isinstance(doc, dict) or not isinstance(doc.get("resources"), dict):
        result.errors.append({"file": path, "error": "no resources mapping in the Heat template"})
        return result
    declared = doc.get("parameters") if isinstance(doc.get("parameters"), dict) else {}
    params = {k: v["default"] for k, v in declared.items() if isinstance(v, dict) and "default" in v and not v.get("hidden")}
    for name, res in doc["resources"].items():
        if len(result.resources) >= MAX_RESOURCES:
            result.truncated = True
            break
        if not isinstance(res, dict) or not isinstance(res.get("type"), str):
            result.errors.append({"file": path, "error": f"resource {str(name)[:80]!r} has no type"})
            continue
        line = yamlutil.line_of(doc["resources"], name)
        props = _value(res.get("properties") or {}, params)
        notes = ["deployed only when its condition holds; the condition was not evaluated"] if "condition" in res else []
        result.resources.append(Resource(
            provider="openstack", service="heat", resource_type=res["type"][:200], logical_name=str(name)[:200], address=str(name)[:200],
            properties=props if isinstance(props, dict) else {}, source=Source(path, line, line, "heat", _PARSER), notes=notes).finalize())
    return result
