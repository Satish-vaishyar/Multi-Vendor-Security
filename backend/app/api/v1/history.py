"""Audit history, drift comparison, trends, change feed, and recurring-audit schedules."""
from __future__ import annotations
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core import config as cfg
from app.core import persist as db
from app.core import schedules
from app.core import security as sec
from app.services import history

router = APIRouter(prefix="/api/v1/history", tags=["history"])
sched_router = APIRouter(prefix="/api/v1/schedules", tags=["schedules"])


def _asset_or_404(asset_id: str) -> dict:
    a = db.get("assets", asset_id)
    if not a:
        raise HTTPException(404, "Asset not found")
    return a


@router.get("/assets/{asset_id}")
def asset_history(asset_id: str, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    _asset_or_404(asset_id)
    snaps = history.list_snapshots(asset_id, limit=limit, offset=offset)
    return cfg.ok({"asset_id": asset_id, "items": [history.summary_view(s) for s in snaps], "limit": limit, "offset": offset})


@router.get("/assets/{asset_id}/compare")
def compare(asset_id: str, from_snapshot: Optional[str] = Query(None, alias="from"),
            to_snapshot: Optional[str] = Query(None, alias="to")):
    """Drift between two runs of one asset. Defaults to previous -> latest."""
    _asset_or_404(asset_id)
    if not (from_snapshot and to_snapshot):
        snaps = history.list_snapshots(asset_id, limit=2)
        if len(snaps) < 2:
            raise HTTPException(409, "At least two audit runs are needed to compare")
        to_snapshot, from_snapshot = snaps[0]["snapshot_id"], snaps[1]["snapshot_id"]
    out = history.compare(asset_id, from_snapshot, to_snapshot)
    if not out:
        raise HTTPException(404, "Snapshot not found for this asset")
    return cfg.ok(out)


@router.get("/assets/{asset_id}/config-diff")
def config_diff(asset_id: str, from_snapshot: str = Query(..., alias="from"), to_snapshot: str = Query(..., alias="to")):
    """Line diff between the configurations behind two runs; secrets are masked, changed secrets only counted."""
    _asset_or_404(asset_id)
    a, b = history.get_snapshot(from_snapshot), history.get_snapshot(to_snapshot)
    if not a or not b or a["asset_id"] != asset_id or b["asset_id"] != asset_id:
        raise HTTPException(404, "Snapshot not found for this asset")
    if not a.get("configuration_id") or not b.get("configuration_id"):
        raise HTTPException(409, "A snapshot has no stored configuration")
    out = history.config_diff(a["configuration_id"], b["configuration_id"])
    if not out:
        raise HTTPException(404, "Configuration no longer available")
    return cfg.ok(out)


@router.get("/trend")
def trend(days: int = Query(90, ge=1, le=730), asset_id: Optional[str] = None):
    if asset_id:
        _asset_or_404(asset_id)
    return cfg.ok({"days": days, "asset_id": asset_id, "points": history.trend(days, asset_id)})


@router.get("/changes")
def changes(days: int = Query(7, ge=1, le=90), limit: int = Query(100, ge=1, le=500), all: bool = False):
    """What changed across the estate: new critical/high findings, severity increases, big score moves."""
    return cfg.ok({"days": days, "items": history.recent_changes(days, limit, only_notable=not all)})


# ------------------------------------------------------------------------------ schedules
class ScheduleBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    asset_id: str = Field(min_length=1, max_length=64)
    interval_minutes: int = Field(default=1440, ge=1)
    frameworks: List[str] = ["CIS", "NIST", "STIG", "ISO27001"]
    run_cve: bool = True
    start_in_minutes: int = Field(default=0, ge=0, le=60 * 24 * 30)


class SchedulePatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    interval_minutes: Optional[int] = Field(default=None, ge=1)
    frameworks: Optional[List[str]] = None
    run_cve: Optional[bool] = None
    enabled: Optional[bool] = None


@sched_router.get("")
def list_schedules(asset_id: Optional[str] = None):
    return cfg.ok({"items": schedules.list_schedules(asset_id)})


@sched_router.post("", status_code=201)
def create_schedule(body: ScheduleBody, user=Depends(sec.require_user)):
    _asset_or_404(body.asset_id)
    try:
        s = schedules.create(body.name, body.asset_id, body.interval_minutes, body.frameworks, body.run_cve,
                             user.get("email") or user.get("id"), body.start_in_minutes)
    except schedules.ScheduleError as e:
        raise HTTPException(400, str(e))
    return cfg.ok(s, "Schedule created")


@sched_router.get("/{schedule_id}")
def get_schedule(schedule_id: str):
    s = schedules.get(schedule_id)
    if not s:
        raise HTTPException(404, "Schedule not found")
    return cfg.ok(s)


@sched_router.patch("/{schedule_id}")
def patch_schedule(schedule_id: str, body: SchedulePatch):
    try:
        s = schedules.update(schedule_id, **body.model_dump(exclude_unset=True))
    except schedules.ScheduleError as e:
        raise HTTPException(400, str(e))
    if not s:
        raise HTTPException(404, "Schedule not found")
    return cfg.ok(s, "Schedule updated")


@sched_router.delete("/{schedule_id}")
def delete_schedule(schedule_id: str):
    if not schedules.delete(schedule_id):
        raise HTTPException(404, "Schedule not found")
    return cfg.ok({"schedule_id": schedule_id}, "Schedule deleted")


@sched_router.post("/{schedule_id}/run")
def run_schedule(schedule_id: str):
    st = schedules.run_now(schedule_id)
    if st is None:
        raise HTTPException(404, "Schedule not found")
    if st != "QUEUED":
        raise HTTPException(409, {"NO_CONFIG": "The asset has no uploaded configuration yet",
                                  "QUEUE_FULL": "Too many pending jobs"}.get(st, st))
    return cfg.ok({"schedule_id": schedule_id, "status": st}, "Audit queued")
