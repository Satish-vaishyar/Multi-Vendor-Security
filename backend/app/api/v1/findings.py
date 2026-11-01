"""Findings unified API (api.md §19-20). Backed by Supabase Postgres."""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from typing import Optional

from app.core import config as cfg
from app.core import persist as db
from app.api.v1.paging import Pager, envelope, pager, paged

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])


@router.get("")
def list_findings(severity: Optional[str] = None, type: Optional[str] = None,
                  asset_id: Optional[str] = None, status: Optional[str] = None,
                  audit_id: Optional[str] = None, engine: Optional[str] = None,
                  dedupe: bool = False, p: Pager = Depends(pager(100))):
    filters = {k: v for k, v in {"severity": severity, "type": type, "asset_id": asset_id,
                                 "status": status, "audit_id": audit_id,
                                 "engine": engine}.items() if v}
    # Projected read: list views never drag full evidence JSONB payloads.
    items, total = paged("findings", p, ["finding_id", "type", "title", "severity",
                                         "asset_id", "status", "audit_id", "engine", "control_id"],
                         search=("title", "finding_id", "control_id", "asset_id"), **filters)
    if dedupe and len(items) > 1:
        from app.services.integration import m8_dedup
        keep = set(m8_dedup([f"{f.get('title','')} {f.get('severity','')}" for f in items]))
        items = [f for i, f in enumerate(items) if i in keep]
    lite = [{"finding_id": f["finding_id"], "type": f.get("type"), "title": f.get("title"),
             "severity": f.get("severity"), "asset_id": f.get("asset_id"),
             "status": f.get("status"), "audit_id": f.get("audit_id"),
             "engine": f.get("engine"), "control_id": f.get("control_id")} for f in items]
    return cfg.ok(envelope(lite, total, p))


@router.get("/{finding_id}")
def get_finding(finding_id: str):
    f = db.get("findings", finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    return cfg.ok(f)
