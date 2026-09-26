"""Configurations: upload / bulk-upload / parse / get / canonical-ir / unknowns (api.md §6-9, §33)."""
from __future__ import annotations
from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from typing import List, Optional

from app.core import config as cfg
from app.core import persist as db
from app.core import store
from app.parsers import ingestion, vendor_detector, canonical as canon

router = APIRouter(prefix="/api/v1/configurations", tags=["configurations"])


def _register(filename: str, content: bytes, asset_id: str, hint_vendor: str = "", hint_platform: str = "") -> dict:
    v = ingestion.validate_upload(filename, content)
    det = vendor_detector.detect_vendor(v["text"], hint_vendor)
    cid = store.nid("CFG")
    rec = {"configuration_id": cid, "asset_id": asset_id, "filename": filename,
           "size": v["size"], "lines": v["lines"], "sha256": v["sha256"],
           "config_text": v["text"], "warnings": v["warnings"],
           "detected_vendor": det["vendor"], "detected_platform": det["platform"],
           "detected_version": det.get("version"), "detection": det,
           "hint_vendor": hint_vendor, "hint_platform": hint_platform,
           "status": "UPLOADED", "created_at": store.now()}
    db.save("configurations", rec)
    return rec


@router.post("/upload")
async def upload(file: UploadFile = File(...), asset_id: str = Form("AST-001"),
                 vendor: str = Form(""), platform: str = Form("")):
    content = await file.read()
    try:
        rec = _register(file.filename or "config.txt", content, asset_id, vendor, platform)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return cfg.ok({"configuration_id": rec["configuration_id"], "filename": rec["filename"],
                   "size": rec["size"], "status": rec["status"],
                   "detected_vendor": rec["detected_vendor"],
                   "detected_platform": rec["detected_platform"],
                   "detected_version": rec["detected_version"]}, "Upload successful")


@router.post("/bulk-upload")
async def bulk_upload(files: List[UploadFile] = File(...), asset_id: str = Form("AST-001")):
    if len(files) > cfg.MAX_BULK_FILES:
        raise HTTPException(400, f"Too many files (max {cfg.MAX_BULK_FILES})")
    batch_id = store.nid("BATCH")
    out, rejected = [], 0
    for f in files:
        try:
            rec = _register(f.filename or "config.txt", await f.read(), asset_id)
            out.append({"configuration_id": rec["configuration_id"], "status": "QUEUED"})
        except ValueError:
            rejected += 1
    return cfg.ok({"batch_id": batch_id, "total_files": len(files),
                   "accepted": len(out), "rejected": rejected, "configurations": out})


@router.post("/{configuration_id}/parse")
def parse(configuration_id: str):
    rec = db.get("configurations", configuration_id)
    if not rec:
        raise HTTPException(404, "Configuration not found")
    parsed = canon.parse_to_canonical(rec["config_text"], rec["detection"]["vendor_id"])
    rec = db.update("configurations", configuration_id,
                    {"status": "PARSED", "canonical_ir": parsed["nested_ir"],
                     "flat_ir": parsed["flat_ir"], "unknown_lines": parsed["unknown_lines"]})
    assert rec is not None
    return cfg.ok({"job_id": store.nid("JOB"), "status": "COMPLETED",
                   "configuration_id": configuration_id}, "Parse completed")


@router.get("/{configuration_id}")
def get_configuration(configuration_id: str):
    rec = db.get("configurations", configuration_id)
    if not rec:
        raise HTTPException(404, "Configuration not found")
    view = {k: v for k, v in rec.items() if k != "config_text"}
    view["parser"] = {"type": "KNOWN_VENDOR" if rec["detected_vendor"] != "UNKNOWN" else "AI_PIPELINE",
                      "confidence": rec["detection"]["confidence"]}
    return cfg.ok(view)


@router.get("/{configuration_id}/canonical-ir")
def get_canonical(configuration_id: str):
    rec = db.get("configurations", configuration_id)
    if not rec:
        raise HTTPException(404, "Configuration not found")
    if "canonical_ir" not in rec:
        parsed = canon.parse_to_canonical(rec["config_text"], rec["detection"]["vendor_id"])
        rec = db.update("configurations", configuration_id,
                        {"canonical_ir": parsed["nested_ir"], "flat_ir": parsed["flat_ir"]})
        assert rec is not None
    return cfg.ok(rec["canonical_ir"])


@router.get("/{configuration_id}/unknowns")
def get_unknowns(configuration_id: str):
    rec = db.get("configurations", configuration_id)
    if not rec:
        raise HTTPException(404, "Configuration not found")
    parsed = canon.parse_to_canonical(rec["config_text"], rec["detection"]["vendor_id"])
    from app.services.integration import m2_score_batch
    scores = m2_score_batch(parsed["unknown_lines"])
    items = [{"id": f"UNK-{i + 1:03d}", "line": l, "context": [], "status": "PENDING_TRAINING",
              "oov": scores[i] if i < len(scores) else {}}
             for i, l in enumerate(parsed["unknown_lines"])]
    for it in items:  # keep training queue in sync for the Training UI
        tid = store.nid("TR")
        db.save("training", {"training_id": tid, "vendor": rec["detected_vendor"],
                             "platform": rec["detected_platform"], "raw_command": it["line"],
                             "context": [], "status": "PENDING", "created_at": store.now()})
    return cfg.ok({"unknown_count": len(items), "items": items})
