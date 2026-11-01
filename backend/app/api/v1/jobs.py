"""Background jobs API: enqueue audits / reports / whole fleets, watch progress, cancel, retry."""
from __future__ import annotations
import re
from typing import List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field

from app.api.v1 import assets as assets_api
from app.api.v1 import configurations as cfg_api
from app.core import config as cfg
from app.core import jobs
from app.core import persist as db
from app.core import security as sec
from app.core import store
from app.parsers import ingestion
from app.services.integration import fingerprint_vendor

router = APIRouter(prefix="/api/v1/jobs", tags=["jobs"])

_FRAMEWORKS = {"CIS", "NIST", "STIG", "ISO27001", "CERTIN"}
_HOSTNAME_RES = [
    re.compile(r"^[ \t]*hostname\s+\"?([\w.\-]+)\"?\s*$", re.I | re.M),                 # IOS / EOS / NX-OS
    re.compile(r"^[ \t]*(?:set\s+system\s+)?host-name\s+\"?([\w.\-]+)\"?;?\s*$", re.I | re.M),   # Junos
    re.compile(r"^[ \t]*set\s+hostname\s+\"?([\w.\-]+)\"?\s*$", re.I | re.M),            # FortiOS
    re.compile(r"^[ \t]*set\s+deviceconfig\s+system\s+hostname\s+\"?([\w.\-]+)\"?\s*$", re.I | re.M),   # PAN-OS
]


class AuditJobBody(BaseModel):
    asset_id: str = Field(min_length=1, max_length=64)
    configuration_id: str = Field(min_length=1, max_length=64)
    frameworks: List[str] = ["CIS", "NIST", "STIG", "ISO27001"]
    run_cve: bool = True
    run_pqc: bool = True
    run_security: bool = True


class ReportJobBody(BaseModel):
    audit_id: str = Field(min_length=1, max_length=64)
    sections: Optional[List[str]] = None


def _frameworks(items: List[str]) -> List[str]:
    out = [f.strip().upper() for f in items if f.strip()]
    bad = [f for f in out if f not in _FRAMEWORKS]
    if bad or not out:
        raise HTTPException(400, f"frameworks must be a non-empty subset of {sorted(_FRAMEWORKS)}")
    return out


def _enqueue(kind: str, payload: dict, user: dict, batch_id: Optional[str] = None) -> str:
    try:
        return jobs.enqueue(kind, payload, batch_id=batch_id, created_by=user.get("email") or user.get("id"))
    except jobs.QueueFull as e:
        raise HTTPException(429, str(e))


@router.post("/audit", status_code=202)
def enqueue_audit(body: AuditJobBody, user=Depends(sec.require_user)):
    if not db.get("configurations", body.configuration_id):
        raise HTTPException(404, "Configuration not found")
    if not db.get("assets", body.asset_id):
        raise HTTPException(404, "Asset not found")
    jid = _enqueue("audit", {**body.model_dump(), "frameworks": _frameworks(body.frameworks)}, user)
    return cfg.ok({"job_id": jid, "status": jobs.QUEUED}, "Audit queued")


@router.post("/report", status_code=202)
def enqueue_report(body: ReportJobBody, user=Depends(sec.require_user)):
    if not db.get("audits", body.audit_id, inflate=False):
        raise HTTPException(404, "Audit not found")
    jid = _enqueue("report", body.model_dump(), user)
    return cfg.ok({"job_id": jid, "status": jobs.QUEUED}, "Report queued")


def _device_name(text: str, filename: str) -> str:
    for rx in _HOSTNAME_RES:
        m = rx.search(text)
        if m:
            return m.group(1)[:200]
    stem = re.sub(r"\.[A-Za-z0-9]{1,5}$", "", (filename or "device").rsplit("/", 1)[-1].rsplit("\\", 1)[-1])
    return (stem or "device")[:200]


@router.post("/bulk-audit", status_code=202)
def bulk_audit(files: List[UploadFile] = File(...), frameworks: str = Form("CIS,NIST,STIG,ISO27001"),
               run_cve: bool = Form(True), criticality: str = Form("MEDIUM"), user=Depends(sec.require_user)):
    """Onboard + audit a whole fleet in the background: one asset per device (named from the config's hostname,
    reused if it already exists), one queued audit job per file, all sharing a batch id."""
    if len(files) > cfg.MAX_BATCH_FILES:
        raise HTTPException(400, f"Too many files (max {cfg.MAX_BATCH_FILES} per batch)")
    fw = _frameworks(frameworks.split(","))
    crit = criticality.strip().upper()
    if crit not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        raise HTTPException(400, "criticality must be LOW, MEDIUM, HIGH or CRITICAL")
    batch_id = store.nid("BATCH")
    accepted, rejected = [], []
    for f in files:
        name = f.filename or "config.txt"
        try:
            content = f.file.read(ingestion.MAX_BYTES + 1)            # spooled to disk by the server, not held in RAM
            v = ingestion.validate_upload(name, content)
            fp = fingerprint_vendor(v["text"]) or {}
            device = _device_name(v["text"], name)
            asset = assets_api.get_or_create_asset(device, vendor=str(fp.get("vendor", "")), criticality=crit)
            rec = cfg_api._register(name, content, asset["asset_id"])
            jid = _enqueue("audit", {"asset_id": asset["asset_id"], "configuration_id": rec["configuration_id"],
                                     "frameworks": fw, "run_cve": run_cve}, user, batch_id)
            accepted.append({"filename": name, "device": device, "asset_id": asset["asset_id"],
                             "configuration_id": rec["configuration_id"], "job_id": jid})
        except HTTPException:
            raise                                                    # queue full etc.: stop the whole batch
        except ValueError as e:
            rejected.append({"filename": name, "reason": str(e)})
    if not accepted:
        raise HTTPException(400, f"No file accepted: {rejected[:3]}")
    return cfg.ok({"batch_id": batch_id, "accepted": len(accepted), "rejected": rejected, "jobs": accepted},
                  f"{len(accepted)} audit(s) queued")


@router.get("")
def list_jobs(status: Optional[str] = None, kind: Optional[str] = None, batch_id: Optional[str] = None,
              limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    items = [jobs.public(j) for j in jobs.list_jobs(status=status, kind=kind, batch_id=batch_id, limit=limit, offset=offset)]
    return cfg.ok({"items": items, "limit": limit, "offset": offset})


@router.get("/batches/{batch_id}")
def batch(batch_id: str):
    s = jobs.batch_summary(batch_id)
    if not s:
        raise HTTPException(404, "Batch not found")
    return cfg.ok(s)


@router.get("/{job_id}")
def get_job(job_id: str):
    j = jobs.get(job_id)
    if not j:
        raise HTTPException(404, "Job not found")
    return cfg.ok(jobs.public(j))


@router.post("/{job_id}/cancel")
def cancel_job(job_id: str):
    st = jobs.cancel(job_id)
    if st is None:
        raise HTTPException(409, "Job not found or already finished")
    return cfg.ok({"job_id": job_id, "status": st}, "Cancelled" if st == jobs.CANCELLED else "Cancellation requested")


@router.post("/{job_id}/retry")
def retry_job(job_id: str):
    if not jobs.retry(job_id):
        raise HTTPException(409, "Only FAILED or CANCELLED jobs can be retried")
    return cfg.ok({"job_id": job_id, "status": jobs.QUEUED}, "Re-queued")
