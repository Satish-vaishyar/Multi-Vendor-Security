"""cloud-init `#cloud-config` parser (RTM S29; CM-058).

The file is read as data and never executed. Secrets are not kept: every password-bearing value (`plain_text_passwd`, `passwd`,
`hashed_passwd`, `password`, `chpasswd` entries) is replaced by a marker that still shows the key was set, and `write_files`
contents are dropped (only path and permissions are retained). `runcmd` is kept because the rules inspect it, and is redacted
again when a report is built.
"""
from __future__ import annotations

import os
from typing import Any

from cloud import yamlutil
from cloud.ir import Resource, Source
from cloud.parsers.terraform import ParseResult

_PARSER = "cloud.parsers.cloudinit 1"
_SECRET_KEYS = {"plain_text_passwd", "plain-text-passwd", "passwd", "hashed_passwd", "hashed-passwd", "password", "list"}
MASK = "[REDACTED]"
MAX_DEPTH = 20


def _scrub(v: Any, depth: int = 0) -> Any:
    if depth > MAX_DEPTH:
        return MASK
    if isinstance(v, dict):
        return {str(k): MASK if str(k) in _SECRET_KEYS and x not in (None, "") else _scrub(x, depth + 1) for k, x in v.items()}
    if isinstance(v, list):
        return [_scrub(x, depth + 1) for x in v]
    return v


def parse_cloud_init(path: str, text: str) -> ParseResult:
    result = ParseResult()
    try:
        doc = yamlutil.load(text)
    except yamlutil.YamlError as e:
        result.errors.append({"file": path, "error": f"invalid YAML: {e}"[:200]})
        return result
    if not isinstance(doc, dict):
        result.errors.append({"file": path, "error": "a #cloud-config file must be a mapping"})
        return result
    props = _scrub({k: v for k, v in doc.items() if k != "write_files"})
    files = doc.get("write_files")
    props["write_files"] = [{"path": str(f.get("path", ""))[:300], "permissions": str(f.get("permissions", "0644"))}
                            for f in files if isinstance(f, dict)] if isinstance(files, list) else []
    name = os.path.basename(path.replace("\\", "/"))[:200] or path
    result.resources.append(Resource(
        provider="cloudinit", service="cloud-init", resource_type="cloudinit_config", logical_name=name, address=path[:300],
        properties=props, source=Source(path, 1, 1, "cloud_init", _PARSER),
        notes=["cloud-init modules other than users, chpasswd, ssh_pwauth and runcmd are not assessed"]).finalize())
    return result
