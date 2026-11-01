"""End-to-end static scan pipeline (RTM S04/S14 engine side; CM-090, CM-120, CM-121, CM-005).

upload bytes -> safe intake -> decode -> format/provider detection -> secret scan (BEFORE parsing) -> parsers ->
rule engine (optional external engines) -> a JSON-safe report with an honest coverage statement.

Nothing here executes uploaded content, fetches anything, or contacts a cloud API. The report never says "compliant",
"certified" or "secure"; it states what was and was not assessed (CAT section 12).
"""
from __future__ import annotations

import hashlib
import os
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from cloud import detect, graph, intake, scanners, secret_scan
from cloud.ir import Finding, Resource, jsonable, resource_to_dict, validate_resource
from cloud.parsers import ansible, arm, cloudformation, cloudinit, heat, kubernetes, pulumi, terraform
from cloud.rules.engine import evaluate
from cloud.rules.customer import load_effective_pack
from cloud.rules.pack import Pack

PIPELINE_VERSION = "1"
MAX_RESOURCES_IN_REPORT = 5000
CAVEAT = ("Static assessment of the uploaded files only: live cloud state, inherited organisation policies and "
          "organisational controls were not assessed.")


def _decode(data: bytes) -> Optional[str]:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


_USERINFO = re.compile(r"(://)[^/@\s]+@")


def _safe_text(value: Any) -> Any:
    """Redact secrets and strip URL userinfo from any string that came from the upload (module sources, parser errors)."""
    if isinstance(value, str):
        return _USERINFO.sub(r"\1", secret_scan.redact(value))
    if isinstance(value, dict):
        return {k: _safe_text(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_safe_text(v) for v in value]
    return value


def _statement(fails: int, unknowns: int) -> str:
    if fails:
        head = f"{fails} violation(s) detected in the uploaded files for the selected rule pack"
    else:
        head = "No violations detected in the uploaded files for the selected rule pack"
    tail = f"; {unknowns} check(s) could not be determined and are reported as UNKNOWN" if unknowns else ""
    return f"{head}{tail}. {CAVEAT}"


def _secret_findings(found: List[secret_scan.SecretFinding]) -> List[Finding]:
    return [Finding(control_id="CLOUD-SEC-001", title=f"Hard-coded secret in uploaded file ({f.kind})", severity="HIGH",
                    evidence_state="FAIL_STATIC", resource_address=f.path, resource_type="file", provider="",
                    evidence=[{"rule": f.rule_id, "preview": f.preview, "fingerprint": f.fingerprint}],
                    source={"file": f.path, "line_start": f.line, "line_end": f.line, "format": "secret_scan"},
                    rule_version="1.0.0", remediation={"summary": "Remove the value, load it from a secret manager, and rotate it: "
                                                                  "a secret in an uploaded file may be exposed even if never deployed."})
            for f in found]


def run_scan(data: bytes, filename: str, workdir: Path, pack: Optional[Pack] = None, allow_state: bool = False,
             salt: Optional[bytes] = None, engines: Sequence[str] = (), limits: intake.Limits = intake.Limits()) -> Dict[str, Any]:
    started = time.time()
    pack = pack or load_effective_pack()
    salt = salt or os.urandom(16)
    report: Dict[str, Any] = {"pipeline_version": PIPELINE_VERSION, "mode": "static", "rule_pack_version": pack.version,
                              "input": {"filename": os.path.basename(filename.replace("\\", "/")), "size_bytes": len(data),
                                        "sha256": hashlib.sha256(data).hexdigest()}}
    try:
        taken = intake.ingest(data, filename, workdir, limits, allow_state)
    except intake.IntakeError as e:
        return {**report, "status": "REJECTED", "error": str(e), "findings": [], "resources": [], "files": [], "rejected": [],
                "coverage": {}, "summary": {}, "statement": f"The upload was refused: {e}. Nothing was assessed."}

    texts: List[Tuple[str, str]] = []
    skipped: List[Dict[str, str]] = []
    for f in taken.files:
        text = _decode((workdir / f.path).read_bytes())
        if text is None:
            skipped.append({"path": f.path, "reason": "not valid UTF-8 text"})
        else:
            texts.append((f.path, text))

    detections = [detect.detect(p, t) for p, t in texts]
    secrets = secret_scan.scan_files(texts, salt)                       # always before any parser
    resources: List[Resource] = []
    errors: List[Dict[str, str]] = []
    unresolved: List[Dict[str, str]] = []
    truncated = False
    tf_files = [(d.path, dict(texts)[d.path]) for d in detections if d.format in ("terraform_hcl", "terraform_json")]
    results = []
    if tf_files:
        results.append(terraform.parse_terraform(tf_files))
    for d in detections:
        text = dict(texts)[d.path]
        if d.format == "terraform_plan":
            results.append(terraform.parse_plan(d.path, text))
        elif d.format == "terraform_state":
            results.append(terraform.parse_state(d.path, text, allow_state))
        elif d.format == "arm":
            results.append(arm.parse_arm(d.path, text))
        elif d.format == "cloudformation":
            results.append(cloudformation.parse_cloudformation(d.path, text))
        elif d.format == "cloud_init":
            results.append(cloudinit.parse_cloud_init(d.path, text))
        elif d.format == "heat":
            results.append(heat.parse_heat(d.path, text))
        elif d.format == "ansible":
            results.append(ansible.parse_ansible(d.path, text))
        elif d.format == "pulumi_export":
            results.append(pulumi.parse_pulumi(d.path, text))
        elif d.format == "kubernetes":
            results.append(kubernetes.parse_kubernetes(d.path, text))
    for r in results:
        resources.extend(r.resources)
        errors.extend(r.errors)
        unresolved.extend(r.unresolved_modules)
        truncated = truncated or r.truncated

    evaluated = evaluate(resources, pack)
    findings = _secret_findings(secrets) + evaluated.findings
    exposure = graph.annotate(findings, resources, incomplete=bool(unresolved) or truncated)
    engine_runs = []
    for name in engines:
        run = scanners.run_engine(name, str(workdir))
        engine_runs.append({"engine": name, "status": run.status, "version": run.version, "error": run.error, "findings": len(run.findings)})
        findings = scanners.merge_findings(findings, run.findings)

    by_state = Counter(f.evidence_state for f in findings)
    by_severity = Counter(f.severity for f in findings if f.evidence_state == "FAIL_STATIC")
    unsupported_formats = Counter(d.format for d in detections if d.format in ("unknown", "bicep", "ros", "rego",
                                                                               "helm_chart"))
    coverage = {**evaluated.coverage, "files_received": len(taken.files) + len(taken.rejected), "files_accepted": len(taken.files),
                "files_rejected": len(taken.rejected) + taken.rejected_overflow, "files_not_text": len(skipped),
                "formats": dict(Counter(d.format for d in detections)), "providers": detect.providers_of(detections),
                "unsupported_formats": dict(unsupported_formats), "modules_not_resolved": len(unresolved),
                "expansion_truncated": truncated, "rule_pack_customisations": pack.customisations, "effective_exposure": exposure, "external_engines": engine_runs,
                "not_assessed": ["live cloud state", "organisation-wide policies", "runtime and image vulnerabilities",
                                 "controls with no rule in this pack"]}
    problems = [p for r in resources for p in validate_resource(r)]
    return {**report, "status": "COMPLETED", "duration_ms": int((time.time() - started) * 1000),
            "files": [{"path": f.path, "size": f.size, "sha256": f.sha256,
                       "format": next((d.format for d in detections if d.path == f.path), "unknown")} for f in taken.files],
            "rejected": [{"path": x.path, "reason": x.reason} for x in taken.rejected] + skipped,
            "resources": [resource_to_dict(r) for r in resources[:MAX_RESOURCES_IN_REPORT]],
            "findings": [f.to_dict() for f in findings], "coverage": coverage,
            "unresolved": _safe_text(jsonable(unresolved, redact=True)),
            "errors": _safe_text(errors + ([{"file": "", "error": "; ".join(problems[:5])}] if problems else [])),
            "summary": {"states": dict(by_state), "failed_by_severity": dict(by_severity), "resources": len(resources)},
            "statement": _statement(by_state.get("FAIL_STATIC", 0), by_state.get("UNKNOWN_STATIC", 0))}
