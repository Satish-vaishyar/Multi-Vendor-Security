"""AI Training loop APIs (api.md §21-25): queue / suggest / approve / reject / job status."""
from __future__ import annotations
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core import config as cfg
from app.core import persist as db
from app.core import security as sec
from app.core import store
from app.api.v1.paging import Pager, envelope, pager, paged
from app.services import integration
from app.services.integration import okf_layer

router = APIRouter(prefix="/api/v1/training", tags=["training"])


@router.get("/queue")
def queue(status: str = "PENDING", vendor: str = "", p: Pager = Depends(pager(200, "asc"))):
    filters = {"status": status, **({"vendor": vendor} if vendor else {})}
    items, total = paged("training", p, None, search=("vendor", "platform", "training_id"), **filters)
    return cfg.ok(envelope(items, total, p))


@router.post("/{training_id}/suggest")
def suggest(training_id: str):
    t = db.get("training", training_id)
    if not t:
        raise HTTPException(404, "Training item not found")
    okf = okf_layer()
    out = okf["learn"].suggest(t["raw_command"], t.get("vendor") or "unknown", t.get("context", []))
    # normalize to api.md §22 shape
    sug = out.get("training_suggestions") or out.get("suggestions") or []
    norm = [{"canonical_property": s.get("canonical_property"), "value": s.get("value", s.get("canonical_value")),
             "confidence": s.get("confidence", 0.5), "source": "llm/heuristic"} for s in sug]
    # M3 Mapping Model top-3 (embedding + kNN over verified mappings) alongside
    from app.services.integration import m3_suggest
    model_sug = [{"canonical_property": s.get("canonical_property"), "value": s.get("value"),
                  "confidence": s.get("confidence", 0.5), "source": "M3-kNN",
                  "evidence": s.get("evidence"), "vendor": s.get("vendor")}
                 for s in m3_suggest(t["raw_command"], t.get("vendor") or "unknown") if s.get("canonical_property")]
    db.update("training", training_id, {"suggestions": norm, "model_suggestions": model_sug})
    return cfg.ok({"training_id": training_id, "suggestions": norm, "model_suggestions": model_sug})


class ApproveBody(BaseModel):
    canonical_property: str = Field(min_length=1, max_length=120)
    canonical_value: Any = None
    comment: str = Field(default="", max_length=1000)


MAX_PATTERN_LEN = 400


def build_safe_pattern(raw_command: str) -> str:
    """Literal, anchored, whitespace-flexible regex for one approved config line.

    Every token is ``re.escape``d, so config text can never inject regex
    operators (no wrong matches, no catastrophic backtracking): the only
    quantifier emitted is a plain whitespace run between literals.
    """
    tokens = (raw_command or "").split()
    if not tokens:
        raise ValueError("empty command")
    return r"^\s*" + r"\s+".join(re.escape(t) for t in tokens) + r"\s*$"


def validate_pattern(pattern: str, raw_command: str) -> None:
    if len(pattern) > MAX_PATTERN_LEN:
        raise ValueError(f"pattern too long (> {MAX_PATTERN_LEN} chars)")
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        raise ValueError(f"pattern does not compile: {e}")
    if not rx.search(raw_command.strip()):  # must at least match the line it was learned from
        raise ValueError("pattern does not match its originating line")


@router.post("/{training_id}/approve")
def approve(training_id: str, body: ApproveBody, user=Depends(sec.require_user)):
    t = db.get("training", training_id)
    if not t:
        raise HTTPException(404, "Training item not found")
    if t.get("status") == "APPROVED":
        raise HTTPException(409, "Training item already approved")
    okf = okf_layer()
    vocab = {p.property_id for p in okf["props"].all()}
    if body.canonical_property not in vocab:
        raise HTTPException(400, f"Unknown canonical property {body.canonical_property!r}")
    if isinstance(body.canonical_value, (dict, list)):
        raise HTTPException(400, "canonical_value must be a scalar (bool, number, string or null)")
    raw = (t.get("raw_command") or "").strip()
    try:
        pattern = build_safe_pattern(raw)
        validate_pattern(pattern, raw)
    except ValueError as e:
        raise HTTPException(400, f"Cannot learn this line: {e}")
    vendor = str(t.get("vendor") or "unknown").lower()
    platform = str(t.get("platform") or "any").lower()
    for existing in db.find("mappings", status="approved"):
        if str(existing.get("vendor", "")).lower() == vendor and existing.get("source_token") == pattern:
            raise HTTPException(409, f"Mapping already exists ({existing.get('id')})")
    mid = store.nid("MAP")
    db.save("mappings", {"id": mid, "mapping_id": mid, "vendor": vendor, "platform": platform,
                         "source_token": pattern,   # DB column name for the regex
                         "canonical_property": body.canonical_property,
                         "canonical_value": body.canonical_value,
                         "confidence": 1.0, "status": "approved", "source": "human_verified",
                         "approved_by": user.get("email"), "comment": body.comment,
                         "created_at": store.now()})
    integration.invalidate_learned()
    pending = len(db.find("training", status="PENDING")) - 1  # this one just got approved
    db.update("training", training_id, {"status": "APPROVED", "mapping_id": mid,
                                        "approved_by": user.get("email")})
    return cfg.ok({"status": "APPROVED", "mapping_id": mid, "registry_updated": True,
                   "retraining_required": pending > 0})


class RejectBody(BaseModel):
    reason: str = Field(default="", max_length=1000)


@router.post("/{training_id}/reject")
def reject(training_id: str, body: RejectBody = RejectBody(), user=Depends(sec.require_user)):
    t = db.get("training", training_id)
    if not t:
        raise HTTPException(404, "Training item not found")
    db.update("training", training_id, {"status": "REJECTED", "reason": body.reason,
                                        "rejected_by": user.get("email")})
    return cfg.ok({"status": "REJECTED", "training_id": training_id})


@router.get("/jobs/{job_id}")
def job_status(job_id: str):
    job = db.get("jobs", job_id)
    if not job:   # background-queue jobs keep their state in columns, not in the legacy `data` blob
        from app.core import jobs as _jobs
        q = _jobs.get(job_id)
        if q:
            return cfg.ok(_jobs.public(q))
        raise HTTPException(404, "Job not found")
    return cfg.ok(job)
