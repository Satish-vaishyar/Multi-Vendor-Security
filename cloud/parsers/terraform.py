"""Terraform / OpenTofu parser (RTM S08; CM-050, CM-051, CM-052, CM-104, CM-105, CM-106).

Static only. It reads HCL/JSON text that was already extracted by `intake`; it never runs terraform, never runs
`init`, never fetches modules, providers or URLs, and never executes provisioners or functions. Anything it cannot
determine from the uploaded files becomes `Unknown`, so rules can answer UNKNOWN instead of a false PASS.

Handled: variables (defaults + tfvars), locals, string templates, count / for_each with literal inputs, local modules
that are part of the upload, jsonencode() of literal documents, dynamic blocks (marked Unknown), plan JSON
(`terraform show -json`) with after_unknown, and opt-in state files (secrets dropped).
"""
from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field
from importlib import metadata
from typing import Any, Dict, List, Optional, Tuple

import hcl2
from hcl2 import SerializationOptions

from cloud import secret_scan
from cloud.detect import _TF_PROVIDER
from cloud.ir import Ref, Resource, Source, Unknown

MAX_MODULE_DEPTH = 5
MAX_INSTANCES = 100
MAX_EXPR_DEPTH = 20
MAX_TOTAL_RESOURCES = 5000       # across all modules and instances of one scan
MAX_MODULE_EXPANSIONS = 200
_OPTS = SerializationOptions(with_meta=False)
_PARSER = "python-hcl2 " + metadata.version("python-hcl2")

_TRAVERSAL = re.compile(r"^(var|local)\.([A-Za-z_][\w-]*)((?:\.[A-Za-z_][\w-]*|\[\d+\]|\[\"[^\"]*\"\])*)$")
_REF = re.compile(r"^(?:data\.)?[A-Za-z_][\w-]*\.[A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*|\[[^\]]*\])*$")
_STEP = re.compile(r"\.([A-Za-z_][\w-]*)|\[(\d+)\]|\[\"([^\"]*)\"\]")
_NUMBER = re.compile(r"^-?\d+(?:\.\d+)?$")
_PURE_EXPR = re.compile(r"^\$\{(.*)\}$", re.S)


@dataclass
class ParseResult:
    resources: List[Resource] = field(default_factory=list)
    errors: List[Dict[str, str]] = field(default_factory=list)
    unresolved_modules: List[Dict[str, str]] = field(default_factory=list)
    truncated: bool = False             # a global expansion budget was exhausted; results are partial
    module_expansions: int = 0


def _unquote(s: str) -> str:
    return s[1:-1] if len(s) >= 2 and s[0] == '"' and s[-1] == '"' else s


# ---------------------------------------------------------------- expression evaluation
class Scope:
    def __init__(self, variables: Dict[str, Any], locals_raw: Dict[str, Any], quoted: bool, ctx: Optional[Dict[str, Any]] = None):
        self.variables, self.locals_raw, self.quoted = variables, locals_raw, quoted
        self.ctx = ctx or {}
        self._local_cache: Dict[str, Any] = {}
        self._resolving: set = set()

    def local(self, name: str) -> Any:
        if name in self._local_cache:
            return self._local_cache[name]
        if name not in self.locals_raw:
            return Unknown("undefined local", f"local.{name}")
        if name in self._resolving:
            return Unknown("circular local", f"local.{name}")
        if len(self._resolving) >= MAX_EXPR_DEPTH:
            return Unknown("locals nested too deeply", f"local.{name}")
        self._resolving.add(name)
        try:
            value = evaluate(self.locals_raw[name], self)
        finally:
            self._resolving.discard(name)
        self._local_cache[name] = value
        return value

    def child(self, ctx: Dict[str, Any], quoted: Optional[bool] = None) -> "Scope":
        """A scope with extra context that shares the local cache AND the cycle guard with its parent."""
        sc = Scope(self.variables, self.locals_raw, self.quoted if quoted is None else quoted, {**self.ctx, **ctx})
        sc._local_cache = self._local_cache
        sc._resolving = self._resolving
        return sc


def _traverse(value: Any, steps: str, expr: str) -> Any:
    for m in _STEP.finditer(steps):
        key = m.group(1) if m.group(1) is not None else m.group(3) if m.group(3) is not None else int(m.group(2))
        if isinstance(value, Unknown) or isinstance(value, Ref):
            return value
        try:
            value = value[key]
        except (KeyError, IndexError, TypeError):
            return Unknown("path not found in value", expr)
    return value


def _split_template(s: str) -> Optional[List[Tuple[bool, str]]]:
    """Split 'a-${x}-b' into [(False,'a-'),(True,'x'),(False,'-b')]; None if a %{directive} is present."""
    out: List[Tuple[bool, str]] = []
    i, buf = 0, []
    while i < len(s):
        if s.startswith("%{", i):
            return None
        if s.startswith("${", i):
            depth, j = 1, i + 2
            while j < len(s) and depth:
                depth += (s[j] == "{") - (s[j] == "}")
                j += 1
            if depth:
                return None
            if buf:
                out.append((False, "".join(buf)))
                buf = []
            out.append((True, s[i + 2:j - 1]))
            i = j
        else:
            buf.append(s[i])
            i += 1
    if buf:
        out.append((False, "".join(buf)))
    return out


def eval_expr(expr: str, scope: Scope, depth: int = 0) -> Any:
    expr = expr.strip()
    if depth > MAX_EXPR_DEPTH:
        return Unknown("expression too deeply nested", expr)
    if expr in ("true", "false"):
        return expr == "true"
    if expr == "null":
        return None
    if _NUMBER.match(expr):
        return float(expr) if "." in expr else int(expr)
    if expr.startswith('"') and expr.endswith('"') and len(expr) >= 2 and "${" not in expr:
        return expr[1:-1]
    m = _TRAVERSAL.match(expr)
    if m:
        base = scope.variables.get(m.group(2), Unknown("variable has no value in the uploaded files", expr)) \
            if m.group(1) == "var" else scope.local(m.group(2))
        return _traverse(base, m.group(3), expr)
    for key in ("count.index", "each.key", "each.value"):
        if expr == key or expr.startswith(key + ".") or expr.startswith(key + "["):
            if key not in scope.ctx:
                return Unknown("outside count/for_each context", expr)
            return _traverse(scope.ctx[key], expr[len(key):], expr)
    if expr.startswith("jsonencode(") and expr.endswith(")"):
        try:
            doc = hcl2.loads("x = " + expr[len("jsonencode("):-1] + "\n", serialization_options=_OPTS)["x"]
        except Exception:                                         # noqa: BLE001 - any parse failure means "unknown"
            return Unknown("jsonencode argument not statically readable", expr)
        return evaluate(doc, scope.child({}, quoted=True), depth + 1)
    if _REF.match(expr):
        return Ref(expr)
    return Unknown("expression needs evaluation (function, conditional or loop)", expr)


def _template(body: str, scope: Scope, depth: int) -> Any:
    parts = _split_template(body)
    if parts is None:
        return Unknown("unsupported template directive", body)
    if len(parts) == 1 and parts[0][0]:
        return eval_expr(parts[0][1], scope, depth + 1)
    out = []
    for is_expr, text in parts:
        if not is_expr:
            out.append(text)
            continue
        v = eval_expr(text, scope, depth + 1)
        if isinstance(v, (Unknown, Ref)) or isinstance(v, (dict, list)):
            return Unknown("string built from a value unknown at scan time", body)
        out.append("" if v is None else str(v).lower() if isinstance(v, bool) else str(v))
    return "".join(out)


def evaluate(value: Any, scope: Scope, depth: int = 0) -> Any:
    if isinstance(value, str):
        if scope.quoted:
            if value.startswith('"') and value.endswith('"') and len(value) >= 2:
                return _template(value[1:-1], scope, depth)
            m = _PURE_EXPR.match(value)
            if m:
                return eval_expr(m.group(1), scope, depth + 1)
            return value
        m = _PURE_EXPR.match(value)
        return eval_expr(m.group(1), scope, depth + 1) if m and _split_template(value) == [(True, m.group(1))] \
            else _template(value, scope, depth)
    if isinstance(value, dict):
        return {_unquote(k) if isinstance(k, str) else k: evaluate(v, scope, depth + 1) for k, v in value.items()
                if k != "__is_block__"}
    if isinstance(value, list):
        return [evaluate(v, scope, depth + 1) for v in value]
    return value


# ---------------------------------------------------------------- source locations
def _block_lines(text: str, header: str) -> Tuple[int, int]:
    """1-based (start, end) of the first block whose header regex matches; (0, 0) when not found."""
    m = re.search(header, text, re.M)
    if not m:
        return 0, 0
    start = text.count("\n", 0, m.start()) + 1
    depth, i, in_str = 0, text.index("{", m.end() - 1) if text[m.end() - 1] == "{" else m.end(), False
    while i < len(text):
        c = text[i]
        if in_str:
            if c == "\\":
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "#" or (c == "/" and text[i:i + 2] == "//"):
            i = text.find("\n", i)
            if i < 0:
                break
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return start, text.count("\n", 0, i) + 1
        i += 1
    return start, start


# ---------------------------------------------------------------- module assembly
@dataclass
class _File:
    path: str
    text: str
    body: Dict[str, Any]
    quoted: bool


def _blocks(body: Dict[str, Any], kind: str) -> List[Tuple[List[str], Dict[str, Any]]]:
    """Return [(labels, content)] for every block of `kind`, for HCL ({"label": {...}}) layout."""
    out: List[Tuple[List[str], Dict[str, Any]]] = []
    for item in body.get(kind, []) if isinstance(body.get(kind), list) else []:
        if kind in ("locals", "terraform", "provider") and not any(isinstance(v, dict) and v.get("__is_block__") for v in item.values()):
            out.append(([], item))
            continue
        _collect_labelled(item, [], out)
    return out


def _collect_labelled(node: Dict[str, Any], labels: List[str], out: list) -> None:
    if node.get("__is_block__"):
        out.append((labels, node))
        return
    for k, v in node.items():
        if isinstance(v, dict):
            _collect_labelled(v, labels + [_unquote(k)], out)


def _json_blocks(body: Dict[str, Any], kind: str, depth: int) -> List[Tuple[List[str], Dict[str, Any]]]:
    """Same as _blocks for the .tf.json layout: {"resource": {"type": {"name": {...}}}} (depth = label count)."""
    section = body.get(kind)
    if section is None:
        return []
    items = section if isinstance(section, list) else [section]
    out: List[Tuple[List[str], Dict[str, Any]]] = []

    def descend(node: Any, labels: List[str], left: int) -> None:
        if not isinstance(node, dict):
            return
        if left == 0:
            out.append((labels, node))
            return
        for k, v in node.items():
            for sub in v if isinstance(v, list) else [v]:
                descend(sub, labels + [k], left - 1)

    for it in items:
        descend(it, [], depth)
    return out


def _parse_file(path: str, text: str, result: ParseResult) -> Optional[_File]:
    is_json = path.lower().endswith(".json")
    try:
        body = json.loads(text) if is_json else hcl2.loads(text, serialization_options=_OPTS_Q)
    except Exception as e:                                       # noqa: BLE001 - hostile input must never crash a scan
        result.errors.append({"file": path, "error": (str(e).splitlines() or ["parse error"])[0][:200]})
        return None
    if not isinstance(body, dict):
        result.errors.append({"file": path, "error": "top level is not an object"})
        return None
    return _File(path, text, body, quoted=not is_json)


_OPTS_Q = SerializationOptions(with_meta=False)


def _sections(f: _File, kind: str, labels: int) -> List[Tuple[List[str], Dict[str, Any]]]:
    return _json_blocks(f.body, kind, labels) if not f.quoted else _blocks(f.body, kind)


def _attrs(content: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in content.items() if k != "__is_block__"}


def _convert_body(content: Dict[str, Any], scope: Scope, notes: List[str], prefix: str = "") -> Dict[str, Any]:
    """Evaluate a resource body: attributes -> values, repeated blocks -> lists of dicts, dynamic -> Unknown."""
    out: Dict[str, Any] = {}
    for key, val in _attrs(content).items():
        if key in ("count", "for_each", "provider", "depends_on", "lifecycle", "connection"):
            continue
        if key == "provisioner" and scope.quoted:
            for item in val:
                notes.extend(f"provisioner:{_unquote(k)}" for k in item)
            continue
        if key == "provisioner":
            notes.extend(f"provisioner:{k}" for k in (val if isinstance(val, dict) else [x for d in val for x in d]))
            continue
        if key == "dynamic":
            for item in val if isinstance(val, list) else [val]:
                for label in item:
                    name = _unquote(label)
                    out[name] = Unknown("dynamic block generated at plan time", f"dynamic.{name}")
            continue
        if scope.quoted and isinstance(val, list) and val and all(isinstance(i, dict) and i.get("__is_block__") for i in val):
            out[key] = [_convert_body(i, scope, notes) for i in val]
        else:
            out[key] = evaluate(val, scope)
    return out


def _instances(content: Dict[str, Any], scope: Scope) -> List[Tuple[str, Dict[str, Any], Optional[str]]]:
    """Expand count / for_each into [(suffix, ctx, note)]; unknown multiplicity yields one instance with a note."""
    if "count" in content:
        n = evaluate(content["count"], scope)
        if isinstance(n, int) and not isinstance(n, bool) and 0 <= n <= MAX_INSTANCES:
            return [(f"[{i}]", {"count.index": i}, None) for i in range(n)]
        return [("", {}, "count is not statically known or exceeds the scan limit")]
    if "for_each" in content:
        fe = evaluate(content["for_each"], scope)
        if isinstance(fe, dict) and len(fe) <= MAX_INSTANCES:
            return [(f'["{k}"]', {"each.key": k, "each.value": v}, None) for k, v in fe.items()]
        if isinstance(fe, list) and len(fe) <= MAX_INSTANCES and all(isinstance(x, str) for x in fe):
            return [(f'["{k}"]', {"each.key": k, "each.value": k}, None) for k in fe]
        return [("", {}, "for_each is not statically known or exceeds the scan limit")]
    return [("", {}, None)]


def _provider_service(rtype: str) -> Tuple[str, str]:
    prefix, _, rest = rtype.partition("_")
    return _TF_PROVIDER.get(prefix, prefix), (rest.split("_", 1)[0] if rest else "")


def _build_module(files: List[_File], variables: Dict[str, Any], mod_prefix: str, depth: int, all_dirs: Dict[str, List[_File]],
                  result: ParseResult, call_dir: str) -> None:
    quoted = files[0].quoted if files else True
    # variables: provided inputs > defaults > unknown
    declared: Dict[str, Any] = {}
    locals_raw: Dict[str, Any] = {}
    for f in files:
        for labels, content in _sections(f, "variable", 1):
            name = labels[0]
            if name in variables:
                declared[name] = variables[name]
            elif "default" in content:
                declared[name] = evaluate(content["default"], Scope({}, {}, f.quoted))
            else:
                declared[name] = Unknown("variable has no default and no value in the uploaded files", f"var.{name}")
        for _labels, content in (_sections(f, "locals", 0) if f.quoted else _json_locals(f)):
            locals_raw.update(_attrs(content))
    for name, val in variables.items():
        declared.setdefault(name, val)
    base = Scope(declared, locals_raw, quoted)

    for f in files:
        sc = Scope(declared, locals_raw, f.quoted)
        sc._local_cache = base._local_cache
        for kind in ("resource", "data"):
            for labels, content in _sections(f, kind, 2):
                rtype, name = labels
                prov, service = _provider_service(rtype)
                for suffix, ctx, note in _instances(content, sc):
                    if len(result.resources) >= MAX_TOTAL_RESOURCES:
                        _truncate(result, "resource")
                        return
                    isc = sc.child(ctx)
                    notes: List[str] = [note] if note else []
                    props = _convert_body(content, isc, notes)
                    header = rf'^\s*{kind}\s+"{re.escape(rtype)}"\s+"{re.escape(name)}"\s*\{{'
                    start, end = _block_lines(f.text, header) if f.quoted else (0, 0)
                    addr = f'{mod_prefix}{"data." if kind == "data" else ""}{rtype}.{name}{suffix}'
                    result.resources.append(Resource(
                        provider=prov, service=service, resource_type=rtype, logical_name=name, address=addr,
                        properties=props, kind=kind, notes=notes,
                        source=Source(f.path, start, end, "terraform_hcl" if f.quoted else "terraform_json", _PARSER),
                        provider_raw=_raw(content)).finalize())
        for labels, content in _sections(f, "module", 1):
            _expand_module(f, labels[0], content, sc, mod_prefix, depth, all_dirs, result, call_dir)


def _truncate(result: ParseResult, what: str) -> None:
    if not result.truncated:
        result.truncated = True
        result.errors.append({"file": "", "error": f"{what} expansion limit reached; the scan result is partial"})


def _raw(content: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(json.dumps(_attrs(content), default=str))


def _json_locals(f: _File) -> List[Tuple[List[str], Dict[str, Any]]]:
    section = f.body.get("locals")
    return [([], d) for d in (section if isinstance(section, list) else [section])] if isinstance(section, (dict, list)) else []


def _expand_module(f: _File, name: str, content: Dict[str, Any], sc: Scope, prefix: str, depth: int,
                   all_dirs: Dict[str, List[_File]], result: ParseResult, call_dir: str) -> None:
    source = evaluate(content.get("source", ""), sc)
    addr = f"{prefix}module.{name}"
    if not isinstance(source, str) or not source.startswith(("./", "../")):
        result.unresolved_modules.append({"module": addr, "source": str(source)[:200], "file": f.path,
                                          "reason": "remote or non-local module is not fetched (offline scan)"})
        return
    target = posixpath.normpath(posixpath.join(call_dir, source))
    result.module_expansions += 1
    if result.module_expansions > MAX_MODULE_EXPANSIONS:
        _truncate(result, "module")
        return
    if depth >= MAX_MODULE_DEPTH:
        result.unresolved_modules.append({"module": addr, "source": source, "file": f.path, "reason": "module nesting too deep"})
        return
    if target not in all_dirs:
        result.unresolved_modules.append({"module": addr, "source": source, "file": f.path,
                                          "reason": "local module path is not part of the upload"})
        return
    inputs = {k: evaluate(v, sc) for k, v in _attrs(content).items()
              if k not in ("source", "version", "count", "for_each", "providers", "depends_on")}
    _build_module(all_dirs[target], inputs, f"{addr}.", depth + 1, all_dirs, result, target)


# ---------------------------------------------------------------- public API
def parse_terraform(files: List[Tuple[str, str]]) -> ParseResult:
    """files: [(relative_path, text)] for .tf / .tf.json / .tfvars / .tfvars.json. Returns every resource with provenance."""
    result = ParseResult()
    parsed: List[_File] = []
    tfvars: Dict[str, Any] = {}
    for path, text in files:
        low = path.lower()
        if low.endswith((".tfvars", ".tfvars.json")):
            f = _parse_file(path, text, result)
            if f:
                sc = Scope({}, {}, f.quoted)
                tfvars_dir = posixpath.dirname(path)
                for k, v in _attrs(f.body).items():
                    tfvars[(tfvars_dir, k)] = evaluate(v, sc)
            continue
        if low.endswith((".tf", ".tf.json")):
            f = _parse_file(path, text, result)
            if f:
                parsed.append(f)
    dirs: Dict[str, List[_File]] = {}
    for f in parsed:
        dirs.setdefault(posixpath.dirname(f.path) or ".", []).append(f)
    called = set()
    for d, fl in dirs.items():
        for f in fl:
            for _l, content in _sections(f, "module", 1):
                src = content.get("source")
                src = _unquote(src) if isinstance(src, str) else ""
                if src.startswith(("./", "../")):
                    called.add(posixpath.normpath(posixpath.join(d, src)))
    for d, fl in sorted(dirs.items()):
        if d in called:
            continue
        variables = {k: v for (vd, k), v in tfvars.items() if (vd or ".") == d}
        try:
            _build_module(fl, variables, "", 0, dirs, result, d)
        except RecursionError:
            result.errors.append({"file": d, "error": "configuration is too deeply nested to evaluate"})
    return result


# ---------------------------------------------------------------- plan JSON / state
def _redact_tree(node: Any) -> Any:
    """Redact secrets in every string leaf (structure-safe, unlike redacting serialised JSON)."""
    if isinstance(node, str):
        return secret_scan.redact(node)
    if isinstance(node, dict):
        return {k: _redact_tree(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_redact_tree(v) for v in node]
    return node


def _unknown_paths(node: Any, prefix: str = "") -> List[str]:
    out: List[str] = []
    if node is True:
        out.append(prefix)
    elif isinstance(node, dict):
        for k, v in node.items():
            out.extend(_unknown_paths(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out.extend(_unknown_paths(v, f"{prefix}[{i}]"))
    return out


_MISSING = object()


def _set_path(tree: Dict[str, Any], dotted: str, value: Any) -> None:
    """Set tree[a][b][0]... = value for 'a.b[0]'; never clobbers known scalars and never raises on odd paths."""
    cur: Any = tree
    parts = re.findall(r"[^.\[\]]+", dotted)
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        if isinstance(cur, list):
            if not part.isdigit() or int(part) >= len(cur):
                return
            key: Any = int(part)
            nxt = cur[key]
        else:                                     # cur is always a dict or list: only containers are ever descended into
            key = part
            nxt = cur.get(key, _MISSING)
        if last:
            cur[key] = value
            return
        if nxt is _MISSING:
            nxt = cur[key] = {}
        elif not isinstance(nxt, (dict, list)):
            return
        cur = nxt


def _plan_resources(module: Dict[str, Any], changes: Dict[str, Any], path: str, out: List[Resource]) -> None:
    for r in module.get("resources", []) or []:
        values = json.loads(json.dumps(r.get("values") or {}))
        for dotted in _unknown_paths(r.get("sensitive_values") or {}):
            _set_path(values, dotted, "[SENSITIVE]")
        values = _redact_tree(values)
        for dotted in _unknown_paths(changes.get(r.get("address"), {})):
            _set_path(values, dotted, Unknown("value is computed at apply time", dotted))
        rtype = r.get("type", "")
        prov, service = _provider_service(rtype)
        out.append(Resource(provider=prov, service=service, resource_type=rtype, logical_name=r.get("name", ""),
                            address=r.get("address", ""), properties=values,
                            kind="data" if r.get("mode") == "data" else "resource",
                            source=Source(path, 0, 0, "terraform_plan", "terraform show -json"),
                            provider_raw={"provider_name": r.get("provider_name", "")}).finalize())
    for child in module.get("child_modules", []) or []:
        _plan_resources(child, changes, path, out)


def parse_plan(path: str, text: str) -> ParseResult:
    """`terraform show -json` output. Values known at plan time are used; after_unknown leaves become Unknown."""
    result = ParseResult()
    try:
        doc = json.loads(text)
    except ValueError as e:
        result.errors.append({"file": path, "error": f"invalid JSON: {e}"[:200]})
        return result
    changes = {c.get("address"): (c.get("change") or {}).get("after_unknown", {})
               for c in doc.get("resource_changes", []) or [] if isinstance(c, dict)}
    root = (doc.get("planned_values") or {}).get("root_module") or {}
    _plan_resources(root, changes, path, result.resources)
    return result


def parse_state(path: str, text: str, allow_state: bool) -> ParseResult:
    """State files hold secrets: refused unless explicitly allowed; sensitive attributes are dropped and strings redacted."""
    result = ParseResult()
    if not allow_state:
        result.errors.append({"file": path, "error": "Terraform state is not parsed without explicit opt-in"})
        return result
    try:
        doc = json.loads(text)
    except ValueError as e:
        result.errors.append({"file": path, "error": f"invalid JSON: {e}"[:200]})
        return result
    for r in doc.get("resources", []) or []:
        for idx, inst in enumerate(r.get("instances", []) or []):
            attrs = dict(inst.get("attributes") or {})
            for s in inst.get("sensitive_attributes", []) or []:
                first = next((p.get("value") for p in s if isinstance(p, dict) and p.get("type") == "get_attr"), None)
                if first in attrs:
                    attrs[first] = "[SENSITIVE]"
            attrs = _redact_tree(attrs)
            rtype = r.get("type", "")
            prov, service = _provider_service(rtype)
            suffix = f"[{idx}]" if len(r.get("instances", [])) > 1 else ""
            result.resources.append(Resource(
                provider=prov, service=service, resource_type=rtype, logical_name=r.get("name", ""),
                address=f'{"data." if r.get("mode") == "data" else ""}{rtype}.{r.get("name", "")}{suffix}',
                properties=attrs, kind="data" if r.get("mode") == "data" else "resource",
                source=Source(path, 0, 0, "terraform_state", "terraform state"), evidence_mode="static",
                notes=["from state: reflects last applied state, not the uploaded configuration"]).finalize())
    return result
