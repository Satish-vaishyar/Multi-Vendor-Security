"""Adapters for external IaC scanners: Checkov and Trivy (RTM S13; CM-091).

The external engines are independent second opinions; Orbit's own deterministic rules stay authoritative for the
evidence-state model. Adapters only normalise what the tools report into `Finding` and tag every result with the
engine name and version, so nothing is presented as an Orbit verdict.

Safety (the uploaded files are hostile, including any tool configuration inside them):
  * tools never run inside the upload: a sanitised COPY is scanned, without tool config, ignore files or Python
  * the working directory and HOME are a fresh, empty, trusted directory, and an empty config file is passed explicitly
  * argument list only (never a shell), hard timeout, scrubbed environment, no stdin, stderr discarded
  * output is read through a bounded stream and the process is killed at the cap, so it is never buffered unbounded
The scanner container has no network (see docker-compose.cloud.yml), so a tool that tries to download policies fails.
The binaries are NOT bundled in the image yet: when absent the run is reported as `unavailable`, never as a clean scan.
"""
from __future__ import annotations

import json
import posixpath
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from cloud.ir import Finding

MAX_OUTPUT_BYTES = 20 * 1024 * 1024
TIMEOUT_SECONDS = 120
_SEVERITY = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFO": "INFO", "UNKNOWN": "INFO"}
DEFAULT_SEVERITY = "MEDIUM"          # Checkov reports no severity in its open-source output; this is a labelled assumption

# External check -> equivalent Orbit control. Maintained by hand; an entry means "same condition", so the duplicate is merged.
EQUIVALENTS: Dict[tuple, str] = {("checkov", "CKV_AWS_24"): "CLOUD-NET-001", ("checkov", "CKV_AWS_25"): "CLOUD-NET-003"}

# Commands are built in one place. Flags must be re-verified against the pinned tool versions when the engines are bundled.
COMMANDS: Dict[str, List[str]] = {
    "checkov": ["checkov", "--config-file", "{empty}", "-d", "{dir}", "--output", "json", "--quiet", "--compact"],
    "trivy": ["trivy", "--config", "{empty}", "config", "--format", "json", "--quiet", "{dir}"],
}
# Files an upload could use to reconfigure a tool, or to run code inside it. They are never copied into the scan directory.
_ALLOWED_SUFFIXES = (".tf", ".tf.json", ".tfvars", ".tfvars.json", ".json", ".yaml", ".yml", ".template", ".hcl")
_TOOL_CONFIG_NAMES = {".checkov.yaml", ".checkov.yml", ".checkov.baseline", "trivy.yaml", "trivy.yml", ".trivyignore", ".trivyignore.yaml",
                      ".trivyignore.yml", "checkov.yaml", "checkov.yml", ".terraformignore"}
VERSION_COMMANDS: Dict[str, List[str]] = {"checkov": ["checkov", "--version"], "trivy": ["trivy", "--version"]}


@dataclass
class EngineRun:
    engine: str
    status: str                          # ok | unavailable | failed
    version: str = ""
    findings: List[Finding] = field(default_factory=list)
    error: str = ""


def _clean_path(path: str, root: str) -> str:
    p = str(path).replace("\\", "/")
    root = root.replace("\\", "/").rstrip("/")
    if root and p.startswith(root + "/"):
        p = p[len(root) + 1:]
    return posixpath.normpath(p.lstrip("/")) if p else ""


def _finding(engine: str, version: str, check_id: str, title: str, severity: str, address: str, provider: str, rtype: str,
             file: str, lines: List[int], remediation: str, url: str) -> Finding:
    start, end = (lines + [0, 0])[:2] if lines else (0, 0)
    return Finding(
        control_id=f"EXT-{engine.upper()}-{check_id}", title=title or check_id, severity=severity, evidence_state="FAIL_STATIC",
        resource_address=address, resource_type=rtype, provider=provider, evidence=[{"engine": engine, "check_id": check_id}],
        source={"file": file, "line_start": int(start or 0), "line_end": int(end or start or 0), "format": "external"},
        rule_version=version, engine=f"{engine} {version}".strip(), frameworks=[],
        remediation={"summary": remediation, "url": url} if (remediation or url) else {})


def parse_checkov(text: str, root: str = "", version: str = "") -> List[Finding]:
    """Checkov JSON: one object, or a list of objects (one per framework). Only failed checks become findings."""
    doc = json.loads(text)
    out: List[Finding] = []
    for part in doc if isinstance(doc, list) else [doc]:
        if not isinstance(part, dict):
            continue
        for chk in (part.get("results") or {}).get("failed_checks") or []:
            sev = str(chk.get("severity") or DEFAULT_SEVERITY).upper()
            address = str(chk.get("resource") or "")
            out.append(_finding("checkov", version, str(chk.get("check_id", "UNKNOWN")), str(chk.get("check_name", "")),
                                _SEVERITY.get(sev, DEFAULT_SEVERITY), address, "", str(part.get("check_type", "")),
                                _clean_path(chk.get("file_path", ""), root), list(chk.get("file_line_range") or []),
                                "", str(chk.get("guideline") or "")))
    return out


def parse_trivy(text: str, root: str = "", version: str = "") -> List[Finding]:
    """Trivy `config` JSON. Only status FAIL becomes a finding (PASS and EXCEPTION are ignored)."""
    doc = json.loads(text)
    out: List[Finding] = []
    for res in (doc.get("Results") or []) if isinstance(doc, dict) else []:
        for m in res.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            cause = m.get("CauseMetadata") or {}
            out.append(_finding("trivy", version, str(m.get("AVDID") or m.get("ID") or "UNKNOWN"), str(m.get("Title", "")),
                                _SEVERITY.get(str(m.get("Severity", "")).upper(), "INFO"), str(cause.get("Resource", "")),
                                str(cause.get("Provider", "")).lower(), str(res.get("Type", "")),
                                _clean_path(res.get("Target", ""), root), [cause.get("StartLine", 0), cause.get("EndLine", 0)],
                                str(m.get("Resolution", "")), str(m.get("PrimaryURL", ""))))
    return out


PARSERS: Dict[str, Callable[..., List[Finding]]] = {"checkov": parse_checkov, "trivy": parse_trivy}


def _scrubbed_env(home: str) -> Dict[str, str]:
    return {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": home, "LANG": "C.UTF-8", "NO_COLOR": "1", "XDG_CONFIG_HOME": home,
            "CHECKOV_RUN_SCA_PACKAGE_SCAN_V2": "false", "TRIVY_NO_PROGRESS": "true", "TRIVY_CACHE_DIR": home}


def prepare_scan_dir(src: str, dst: str) -> int:
    """Copy only plain IaC files (no tool config, ignore files, Python or anything else) into `dst`. Returns the count."""
    n = 0
    for f in sorted(Path(src).rglob("*")):
        rel = f.relative_to(src)
        low = f.name.lower()
        if not f.is_file() or f.is_symlink() or low in _TOOL_CONFIG_NAMES or not low.endswith(_ALLOWED_SUFFIXES):
            continue
        out = Path(dst) / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(f, out)
        n += 1
    return n


def _run_bounded(cmd: List[str], cwd: str, env: Dict[str, str], popen: Callable[..., Any]) -> Tuple[bytes, Optional[int], bool]:
    """Run `cmd`, reading at most MAX_OUTPUT_BYTES+1 of stdout. Returns (output, returncode, too_large). Raises TimeoutExpired."""
    proc = popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, cwd=cwd, env=env, shell=False)
    fired = threading.Event()

    def _kill() -> None:
        fired.set()
        proc.kill()

    timer = threading.Timer(TIMEOUT_SECONDS, _kill)
    timer.start()
    try:
        data = proc.stdout.read(MAX_OUTPUT_BYTES + 1)
        if len(data) > MAX_OUTPUT_BYTES:
            proc.kill()
            proc.wait()
            return data[:0], None, True
        proc.wait()
    finally:
        timer.cancel()
    if fired.is_set():
        raise subprocess.TimeoutExpired(cmd, TIMEOUT_SECONDS)
    return data, proc.returncode, False


def run_engine(name: str, workdir: str, popen: Callable[..., Any] = subprocess.Popen,
               which: Callable[[str], Optional[str]] = shutil.which) -> EngineRun:
    """Run one engine over a sanitised copy of an already-extracted directory. Never raises."""
    if name not in COMMANDS:
        return EngineRun(name, "failed", error="unknown engine")
    if which(COMMANDS[name][0]) is None:
        return EngineRun(name, "unavailable", error=f"{name} is not installed in this scanner image")
    with tempfile.TemporaryDirectory(prefix="engine-") as trusted:
        scan_dir = str(Path(trusted) / "scan")
        empty_cfg = str(Path(trusted) / "empty.yaml")
        Path(empty_cfg).write_text("{}\n", encoding="utf-8")
        Path(scan_dir).mkdir()
        prepare_scan_dir(workdir, scan_dir)
        home = str(Path(trusted) / "home")
        Path(home).mkdir()
        env = _scrubbed_env(home)
        try:
            ver, _rc, _big = _run_bounded(VERSION_COMMANDS[name], trusted, env, popen)
            version = (ver.decode("utf-8", "replace").strip().splitlines() or [""])[-1]
            out, rc, too_large = _run_bounded([a.replace("{dir}", scan_dir).replace("{empty}", empty_cfg) for a in COMMANDS[name]],
                                              trusted, env, popen)
        except subprocess.TimeoutExpired:
            return EngineRun(name, "failed", error="timed out")
        except OSError as e:
            return EngineRun(name, "failed", error=f"could not start: {e.__class__.__name__}")
    if too_large:
        return EngineRun(name, "failed", version=version, error="output too large")
    if not out.strip() or rc not in (0, 1):                  # both tools exit 1 when they report findings
        return EngineRun(name, "failed", version=version, error=f"exit code {rc}")
    try:
        findings = PARSERS[name](out.decode("utf-8", "replace"), scan_dir, version)
    except (ValueError, TypeError, AttributeError) as e:
        return EngineRun(name, "failed", version=version, error=f"unreadable output: {e.__class__.__name__}")
    return EngineRun(name, "ok", version=version, findings=findings)


def merge_findings(own: List[Finding], external: List[Finding]) -> List[Finding]:
    """Add external findings, merging those that duplicate an Orbit result (same control, resource and file)."""
    merged = list(own)
    seen = set()
    for f in external:
        engine = f.engine.split(" ")[0]
        check = f.control_id.rsplit("-", 1)[-1] if f.control_id.count("-") >= 2 else f.control_id
        check = f.evidence[0]["check_id"] if f.evidence else check
        equivalent = EQUIVALENTS.get((engine, check))
        match = next((o for o in own if equivalent and o.control_id == equivalent and o.evidence_state == "FAIL_STATIC"
                      and o.resource_address == f.resource_address and o.source.get("file") == f.source.get("file")), None)
        if match is not None:
            note = f"also reported by {f.engine} {check}"
            if note not in match.notes:
                match.notes.append(note)
            continue
        key = (f.control_id, f.resource_address, f.source.get("file"), f.source.get("line_start"))
        if key not in seen:
            seen.add(key)
            merged.append(f)
    return merged
