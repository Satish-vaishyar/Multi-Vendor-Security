"""Assets CRUD (api.md §5). Backed by Supabase Postgres — no in-memory data."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional

from app.core import config as cfg
from app.core import persist as db
from app.core import store

router = APIRouter(prefix="/api/v1/assets", tags=["assets"])


class AssetBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    vendor: str = Field(default="", max_length=100)
    product: str = Field(default="", max_length=100)
    model: str = Field(default="", max_length=100)
    version: str = Field(default="", max_length=50)
    serial_number: str = Field(default="", max_length=100)
    ip_address: str = Field(default="", max_length=50)
    environment: str = Field(default="", max_length=50)
    criticality: str = Field(default="MEDIUM", max_length=20)


@router.post("")
def create_asset(body: AssetBody):
    aid = store.nid("AST")
    rec = {**body.model_dump(), "asset_id": aid, "status": "ACTIVE", "created_at": store.now()}
    rec["name"] = rec["name"].strip()
    db.save("assets", rec)
    return cfg.ok(rec, "Asset created successfully")


@router.get("")
def list_assets(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
                vendor: Optional[str] = None, status: Optional[str] = None):
    filters = {k: v for k, v in {"vendor": vendor, "status": status}.items() if v}
    items = db.find("assets", **filters)
    total = len(items)
    start = (page - 1) * page_size
    return cfg.ok({"items": items[start:start + page_size], "page": page, "page_size": page_size, "total": total})


@router.get("/{asset_id}")
def get_asset(asset_id: str):
    rec = db.get("assets", asset_id)
    if not rec:
        raise HTTPException(404, "Asset not found")
    return cfg.ok(rec)


@router.patch("/{asset_id}")
def patch_asset(asset_id: str, body: dict):
    body.pop("asset_id", None)
    rec = db.update("assets", asset_id, body)
    if not rec:
        raise HTTPException(404, "Asset not found")
    return cfg.ok(rec, "Asset updated")


@router.delete("/{asset_id}")
def delete_asset(asset_id: str):
    rec = db.update("assets", asset_id, {"status": "DELETED"})
    if not rec:
        raise HTTPException(404, "Asset not found")
    return cfg.ok(rec, "Asset soft-deleted")
