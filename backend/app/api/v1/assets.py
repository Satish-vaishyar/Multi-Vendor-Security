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


def _norm(v: object) -> str:
    return str(v or "").strip().lower()


def _find_duplicate(name: str, vendor: str, product: str, serial: str) -> dict | None:
    """An ACTIVE asset with the same identity (name + vendor + product).

    Distinct non-empty serial numbers mean different hardware sharing a
    hostname — those are never treated as duplicates.
    """
    for a in db.find("assets", status="ACTIVE"):
        if _norm(a.get("name")) != _norm(name):
            continue
        if _norm(a.get("vendor")) != _norm(vendor):
            continue
        if _norm(a.get("product")) != _norm(product):
            continue
        s1, s2 = _norm(a.get("serial_number")), _norm(serial)
        if s1 and s2 and s1 != s2:
            continue
        return a
    return None


@router.post("")
def create_asset(body: AssetBody):
    dupe = _find_duplicate(body.name, body.vendor, body.product, body.serial_number)
    if dupe:
        return cfg.ok(dupe, f"Asset already exists — reusing {dupe.get('asset_id')}")
    aid = store.nid("AST")
    rec = {**body.model_dump(), "asset_id": aid, "status": "ACTIVE", "created_at": store.now()}
    rec["name"] = rec["name"].strip()
    db.save("assets", rec)
    return cfg.ok(rec, "Asset created successfully")


@router.post("/merge-duplicates")
def merge_duplicates():
    """Merge redundant ACTIVE assets sharing one identity.

    Survivor = earliest created. Configurations, audits and findings pointing
    at losers are re-pointed to the survivor; losers are soft-deleted.
    Groups with conflicting non-empty serials are skipped, never merged.
    """
    groups: dict = {}
    for a in db.find("assets", status="ACTIVE"):
        key = (_norm(a.get("name")), _norm(a.get("vendor")), _norm(a.get("product")))
        groups.setdefault(key, []).append(a)
    pk_of = {"configurations": "configuration_id", "audits": "audit_id", "findings": "finding_id"}
    report = []
    for (name, vendor, product), members in groups.items():
        if len(members) < 2:
            continue
        serials = {_norm(m.get("serial_number")) for m in members if _norm(m.get("serial_number"))}
        if len(serials) > 1:
            report.append({"name": name or "—", "vendor": vendor or "—",
                           "status": "skipped_serial_conflict", "members": len(members)})
            continue
        members.sort(key=lambda r: (r.get("created_at") or 0))
        survivor, losers = members[0], members[1:]
        moved = {"configurations": 0, "audits": 0, "findings": 0}
        for loser in losers:
            lid = loser["asset_id"]
            for entity in ("configurations", "audits", "findings"):
                for row in db.find(entity, asset_id=lid):
                    db.update(entity, row[pk_of[entity]], {"asset_id": survivor["asset_id"]})
                    moved[entity] += 1
            db.update("assets", lid, {"status": "DELETED"})
        report.append({"name": survivor.get("name"), "vendor": survivor.get("vendor"),
                       "survivor": survivor["asset_id"],
                       "merged": [m["asset_id"] for m in losers], "moved": moved,
                       "status": "merged"})
    return cfg.ok({"groups": report, "total_merged": sum(len(g.get("merged", [])) for g in report)},
                  "Duplicate merge completed")


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
