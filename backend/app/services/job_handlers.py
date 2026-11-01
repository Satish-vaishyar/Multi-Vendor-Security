"""Job handlers: the work a queued job performs. Each takes the claimed job dict (tenant already bound by
the worker) and returns a JSON-serialisable result. Raise ``PermanentJobError`` for failures that retrying
cannot fix (bad input, missing record); any other exception is retried with backoff.

Handlers are idempotent: audit ids are deterministic per (org, asset, config) and findings are upserted, so a
retry after a crash never duplicates data.
"""
from __future__ import annotations
from typing import Any, Callable, Dict

from app.core import persist as db
from app.services import audit_service


class PermanentJobError(Exception):
    """Do not retry: the job can never succeed as submitted."""


def audit(job: Dict[str, Any]) -> Dict[str, Any]:
    p = job["payload"]
    conf = db.get("configurations", str(p.get("configuration_id", "")))
    if not conf:
        raise PermanentJobError("configuration not found (deleted or other organisation)")
    asset = db.get("assets", str(p.get("asset_id") or conf.get("asset_id") or ""))
    if not asset:
        raise PermanentJobError("asset not found")
    try:
        rec = audit_service.run_audit(
            asset_id=asset["asset_id"], configuration_id=conf["configuration_id"], config_text=conf["config_text"],
            frameworks=list(p.get("frameworks") or ["CIS", "NIST", "STIG", "ISO27001"]),
            run_cve=bool(p.get("run_cve", True)), run_pqc=bool(p.get("run_pqc", True)),
            run_security=bool(p.get("run_security", True)),
            asset_criticality=str(asset.get("criticality") or "MEDIUM"), detected=conf.get("detection"),
            trigger="schedule" if p.get("schedule_id") else ("batch" if job.get("batch_id") else "manual"))
    except (KeyError, ValueError) as e:      # malformed config content that no retry will fix
        raise PermanentJobError(f"audit rejected the input: {e}")
    s = rec.get("summary") or {}
    return {"audit_id": rec["audit_id"], "asset_id": asset["asset_id"], "compliance_score": s.get("compliance_score"),
            "coverage_pct": s.get("coverage_pct"), "failed": s.get("failed"), "degraded": rec.get("degraded", []),
            "changes": rec.get("history") or {}}


def report(job: Dict[str, Any]) -> Dict[str, Any]:
    from app.api.v1.reports import generate_report
    p = job["payload"]
    try:
        out = generate_report(str(p.get("audit_id", "")), p.get("sections"))
    except LookupError:
        raise PermanentJobError("audit not found")
    return {"report_id": out["report_id"], "audit_id": out["audit_id"], "download_url": out["download_url"]}


def webhook(job: Dict[str, Any]) -> Dict[str, Any]:
    from app.services import events
    return events.deliver(job)


def collect(job: Dict[str, Any]) -> Dict[str, Any]:
    """Pull the configuration from the device over read-only SSH, register it like an upload, optionally audit it."""
    from app.core import collector
    from app.services import collection
    p = job["payload"]
    asset_id = str(p.get("asset_id", ""))
    if not db.get("assets", asset_id):
        raise PermanentJobError("asset not found")
    try:
        rec = collection.collect_now(asset_id)
    except collector.CollectError as e:
        # host-key mismatch / bad credentials / unreachable: retrying the same call changes nothing the operator must not see
        raise PermanentJobError(f"collection failed: {e}")
    out: Dict[str, Any] = {"asset_id": asset_id, "configuration_id": rec["configuration_id"], "lines": rec["lines"],
                           "detected_vendor": rec["detected_vendor"]}
    if p.get("audit", True):
        out["audit"] = audit({"payload": {"asset_id": asset_id, "configuration_id": rec["configuration_id"]}, "batch_id": None})
    return out


HANDLERS: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {"audit": audit, "report": report, "webhook": webhook,
                                                                    "collect": collect}
