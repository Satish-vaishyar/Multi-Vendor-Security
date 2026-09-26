"""AI Training loop APIs (api.md §21-25): queue / suggest / approve / reject / job status."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional

from app.core import config as cfg
from app.core import persist as db
from app.core import store
from app.services.integration import okf_layer

router = APIRouter(prefix="/api/v1/training", tags=["training"])


@router.get("/queue")
def queue(status: str = "PENDING"):
    items = db.find("training", status=status)
    return cfg.ok({"items": items, "total": len(items)})


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
    canonical_property: str
    canonical_value: object = None
    comment: str = ""


@router.post("/{training_id}/approve")
def approve(training_id: str, body: ApproveBody):
    t = db.get("training", training_id)
    if not t:
        raise HTTPException(404, "Training item not found")
    okf = okf_layer()
    pattern = t["raw_command"].strip().replace(" ", r"\s+")
    m = okf["maps"].approve(t.get("vendor") or "unknown", t.get("platform") or "any",
                            pattern, body.canonical_property, body.canonical_value)
    mid = store.nid("MAP")
    db.save("mappings", {"id": mid, "mapping_id": mid, **m.model_dump(),
                         "comment": body.comment, "created_at": store.now()})
    pending = len(db.find("training", status="PENDING")) - 1  # this one just got approved
    db.update("training", training_id, {"status": "APPROVED", "mapping_id": mid})
    return cfg.ok({"status": "APPROVED", "mapping_id": mid, "registry_updated": True,
                   "retraining_required": pending > 0})


@router.post("/{training_id}/reject")
def reject(training_id: str, body: dict):
    t = db.get("training", training_id)
    if not t:
        raise HTTPException(404, "Training item not found")
    db.update("training", training_id, {"status": "REJECTED", "reason": body.get("reason", "")})
    return cfg.ok({"status": "REJECTED", "training_id": training_id})


@router.get("/jobs/{job_id}")
def job_status(job_id: str):
    job = db.get("jobs", job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return cfg.ok(job)
