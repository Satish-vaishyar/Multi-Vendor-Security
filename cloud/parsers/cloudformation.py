"""CloudFormation / SAM parser (RTM S09; CM-053).

Static and offline. Intrinsic functions are resolved only when every input is known from the template itself
(parameter defaults, Mappings, literals); anything else becomes `Unknown`. Resource references (!Ref, !GetAtt) become
`Ref` nodes for the relationship graph. SAM resources are kept as their AWS::Serverless::* types (the transform is not
expanded offline) and flagged. Nested stacks, macros and transforms are never fetched or executed.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from cloud import yamlutil
from cloud.ir import Ref, Resource, Source, Unknown
from cloud.parsers.terraform import ParseResult

_PARSER = "cloud.parsers.cloudformation 1"
_SUB_VAR = re.compile(r"\$\{([^}]+)\}")


class _Ctx:
    def __init__(self, doc: Dict[str, Any]):
        self.params = {k: v for k, v in (doc.get("Parameters") or {}).items() if isinstance(v, dict)}
        self.mappings = doc.get("Mappings") or {}
        self.resources = doc.get("Resources") or {}


def _param(name: str, ctx: _Ctx) -> Any:
    p = ctx.params[name]
    if "Default" in p:
        return p["Default"]
    return Unknown("parameter has no default in the template", f"Ref {name}")


def _sub(body: str, extra: Dict[str, Any], ctx: _Ctx) -> Any:
    def repl(name: str) -> Any:
        if name in extra:
            return extra[name]
        if name in ctx.params:
            return _param(name, ctx)
        if name in ctx.resources:
            return Ref(name)
        if "." in name and name.split(".", 1)[0] in ctx.resources:
            return Ref(name)
        return Unknown("pseudo parameter or unresolved name", name)

    out, pos = [], 0
    for m in _SUB_VAR.finditer(body):
        out.append(body[pos:m.start()])
        v = repl(m.group(1).strip())
        if isinstance(v, (Unknown, Ref)) or isinstance(v, (dict, list)):
            return Unknown("Fn::Sub uses a value unknown at scan time", body)
        out.append("" if v is None else str(v))
        pos = m.end()
    out.append(body[pos:])
    return "".join(out)


def evaluate(node: Any, ctx: _Ctx) -> Any:
    if isinstance(node, dict):
        if len(node) == 1:
            (fn, arg), = node.items()
            if fn == "Ref":
                if not isinstance(arg, str):
                    return Unknown("malformed Ref", str(arg))
                if arg in ctx.params:
                    return _param(arg, ctx)
                if arg in ctx.resources:
                    return Ref(arg)
                return Unknown("pseudo parameter or unknown reference", arg)
            if fn == "Fn::GetAtt":
                parts = arg.split(".", 1) if isinstance(arg, str) else arg
                if isinstance(parts, list) and len(parts) == 2 and all(isinstance(p, str) for p in parts):
                    return Ref(f"{parts[0]}.{parts[1]}")
                return Unknown("malformed Fn::GetAtt", str(arg))
            if fn == "Fn::Sub":
                if isinstance(arg, str):
                    return _sub(arg, {}, ctx)
                if isinstance(arg, list) and len(arg) == 2 and isinstance(arg[0], str) and isinstance(arg[1], dict):
                    return _sub(arg[0], {k: evaluate(v, ctx) for k, v in arg[1].items()}, ctx)
                return Unknown("malformed Fn::Sub", str(arg))
            if fn == "Fn::Join":
                if isinstance(arg, list) and len(arg) == 2 and isinstance(arg[0], str) and isinstance(arg[1], list):
                    parts = [evaluate(p, ctx) for p in arg[1]]
                    if all(isinstance(p, (str, int, float, bool)) for p in parts):
                        return arg[0].join(str(p) for p in parts)
                return Unknown("Fn::Join has an input unknown at scan time", "Fn::Join")
            if fn == "Fn::Select":
                if isinstance(arg, list) and len(arg) == 2:
                    idx, seq = evaluate(arg[0], ctx), evaluate(arg[1], ctx)
                    if isinstance(idx, (int, str)) and str(idx).isdigit() and isinstance(seq, list) and int(idx) < len(seq):
                        return seq[int(idx)]
                return Unknown("Fn::Select input unknown at scan time", "Fn::Select")
            if fn == "Fn::FindInMap":
                if isinstance(arg, list) and len(arg) == 3:
                    m, k1, k2 = (evaluate(a, ctx) for a in arg)
                    try:
                        return ctx.mappings[m][k1][k2]
                    except (KeyError, TypeError):
                        pass
                return Unknown("Fn::FindInMap input unknown at scan time", "Fn::FindInMap")
            if fn == "Fn::Base64":
                return evaluate(arg, ctx)
            if fn.startswith("Fn::"):
                return Unknown(f"{fn} is not evaluated offline (conditionals, imports, macros)", fn)
        return {k: evaluate(v, ctx) for k, v in node.items()}
    if isinstance(node, list):
        return [evaluate(v, ctx) for v in node]
    return node


def parse_cloudformation(path: str, text: str) -> ParseResult:
    """Parse one CloudFormation/SAM template (YAML or JSON)."""
    result = ParseResult()
    try:
        doc = yamlutil.load(text)
    except yamlutil.YamlError as e:
        result.errors.append({"file": path, "error": f"invalid template: {e}"[:200]})
        return result
    if not isinstance(doc, dict) or not isinstance(doc.get("Resources"), dict):
        result.errors.append({"file": path, "error": "no Resources section"})
        return result
    ctx = _Ctx(doc)
    sam = "Transform" in doc
    for logical, body in ctx.resources.items():
        if not isinstance(body, dict) or not isinstance(body.get("Type"), str):
            result.errors.append({"file": path, "error": f"resource {logical!r} has no Type"})
            continue
        rtype = body["Type"]
        parts = rtype.split("::")
        service = parts[1].lower() if len(parts) > 1 else ""
        notes: List[str] = []
        confidence = 1.0
        if "Condition" in body:
            notes.append(f"conditional resource (Condition: {body['Condition']})")
            confidence = 0.5
        if rtype.startswith("AWS::Serverless::"):
            notes.append("SAM resource: transform not expanded offline")
        if rtype == "AWS::CloudFormation::Stack":
            result.unresolved_modules.append({"module": logical, "source": json.dumps(evaluate(
                (body.get("Properties") or {}).get("TemplateURL"), ctx), default=str)[:200], "file": path,
                "reason": "nested stack is not fetched (offline scan)"})
        props = evaluate(body.get("Properties") or {}, ctx)
        line = yamlutil.line_of(ctx.resources, logical)
        res = Resource(provider="aws" if rtype.startswith(("AWS::", "Alexa::")) else (parts[0].lower() or "unknown"),
                       service=service, resource_type=rtype, logical_name=logical, address=logical,
                       properties=props if isinstance(props, dict) else {"value": props}, notes=notes,
                       confidence=confidence,
                       source=Source(path, line, line, "cloudformation" if not sam else "cloudformation_sam", _PARSER),
                       provider_raw=json.loads(json.dumps(body.get("Properties") or {}, default=str)))
        for dep in ([body["DependsOn"]] if isinstance(body.get("DependsOn"), str) else body.get("DependsOn") or []):
            if isinstance(dep, str):
                res.relationships.append({"type": "DEPENDS_ON", "field": "DependsOn", "target": dep})
        result.resources.append(res.finalize())
    return result
