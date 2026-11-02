"""Cloud module extras API (docs/CLOUD_MODULE_RTM.md S23): recurring scans of a kept file, links from cloud events to existing
webhooks, opt-in links from a scan to an existing asset. Mounted under the cloud router, so it exists only when the module is on and
every route re-checks the flag. Reads need a signed-in user; changes need AUDITOR, and linking a webhook needs ADMIN."""
from __future__ import annotations
import re
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core import auditlog
from app.core import cloud_ext as ext
from app.core import config as cfg
from app.core import security as sec

router = APIRouter()
_SCAN_ID = re.compile(r"^CSCAN-[0-9a-f]{16}$")
_SCHEDULE_ID = re.compile(r"^CSCH-[0-9a-f]{12}$")
_WEBHOOK_ID = re.compile(r"^WHK-[0-9A-Fa-f]{10}$")
_ASSET_ID = re.compile(r"^[\w.:\-]{1,100}$")


def _guard() -> None:
    from app.api.v1 import cloud
    cloud._guard()


def _scan(scan_id: str) -> str:
    if not _SCAN_ID.match(scan_id):
        raise HTTPException(404, "scan not found")
    return scan_id


def _sched(schedule_id: str) -> str:
    if not _SCHEDULE_ID.match(schedule_id):
        raise HTTPException(404, "schedule not found")
    return schedule_id


def _who(user) -> str:
    return str(user.get("email") or user.get("id") or "unknown")


def _bad(e: Exception):
    return HTTPException(400, str(e))


class ScheduleIn(BaseModel):
    scan_id: str
    interval_minutes: int = Field(ge=ext.MIN_INTERVAL_MINUTES, le=ext.MAX_INTERVAL_MINUTES)
    name: Optional[str] = Field(None, max_length=200)


class SchedulePatch(BaseModel):
    enabled: Optional[bool] = None
    interval_minutes: Optional[int] = Field(None, ge=ext.MIN_INTERVAL_MINUTES, le=ext.MAX_INTERVAL_MINUTES)


class WebhookLinkIn(BaseModel):
    events: List[str] = Field(min_length=1, max_length=len(ext.CLOUD_EVENTS))


class AssetLinkIn(BaseModel):
    asset_id: str


# ------------------------------------------------------------------------------------------------ schedules
@router.get("/schedules")
def list_schedules(user=Depends(sec.require_user)):
    _guard()
    return cfg.ok({"items": ext.list_schedules(), "limits": {"min_interval_minutes": ext.MIN_INTERVAL_MINUTES,
                                                              "max_schedules": ext.MAX_SCHEDULES_PER_ORG,
                                                              "retention_days": ext.SOURCE_RETENTION_DAYS}})


@router.post("/schedules", status_code=201)
def create_schedule(body: ScheduleIn, user=Depends(sec.require_role("AUDITOR"))):
    _guard()
    try:
        s = ext.create_schedule(_scan(body.scan_id), body.name or "", body.interval_minutes, _who(user))
    except ext.ExtError as e:
        raise _bad(e)
    auditlog.record("cloud.schedule.created", actor=user, detail={"schedule_id": s["schedule_id"], "scan_id": body.scan_id,
                                                                   "interval_minutes": body.interval_minutes})
    return cfg.ok(s)


@router.patch("/schedules/{schedule_id}")
def update_schedule(schedule_id: str, body: SchedulePatch, user=Depends(sec.require_role("AUDITOR"))):
    _guard()
    try:
        s = ext.update_schedule(_sched(schedule_id), enabled=body.enabled, interval_minutes=body.interval_minutes)
    except ext.ExtError as e:
        raise _bad(e)
    if not s:
        raise HTTPException(404, "schedule not found")
    auditlog.record("cloud.schedule.updated", actor=user, detail={"schedule_id": schedule_id, "enabled": body.enabled,
                                                                   "interval_minutes": body.interval_minutes})
    return cfg.ok(s)


@router.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: str, user=Depends(sec.require_role("AUDITOR"))):
    _guard()
    if not ext.delete_schedule(_sched(schedule_id)):
        raise HTTPException(404, "schedule not found")
    auditlog.record("cloud.schedule.deleted", actor=user, detail={"schedule_id": schedule_id})
    return cfg.ok({"deleted": True})


@router.post("/schedules/{schedule_id}/run")
def run_schedule_now(schedule_id: str, user=Depends(sec.require_role("AUDITOR"))):
    """Run the kept file once now (same path as the runner). Does not move the schedule's next run."""
    _guard()
    s = ext.get_schedule(_sched(schedule_id))
    if not s:
        raise HTTPException(404, "schedule not found")
    from app.core import cloud_runner
    status, scan_id = cloud_runner.run_source(s["source_id"], _who(user), user)
    ext.record_run(schedule_id, scan_id, status)
    return cfg.ok({"status": status, "scan_id": scan_id})


@router.delete("/scans/{scan_id}/source")
def delete_kept_file(scan_id: str, user=Depends(sec.require_role("AUDITOR"))):
    """Delete the kept copy of an uploaded file; recurring scans that use it are removed with it."""
    _guard()
    if not ext.delete_source(_scan(scan_id)):
        raise HTTPException(404, "no kept file for this scan")
    auditlog.record("cloud.source.deleted", actor=user, detail={"scan_id": scan_id})
    return cfg.ok({"deleted": True})


@router.get("/scans/{scan_id}/source")
def kept_file_info(scan_id: str, user=Depends(sec.require_user)):
    """Whether a kept copy exists (metadata only; the content is never returned)."""
    _guard()
    src = ext.source_for_scan(_scan(scan_id))
    return cfg.ok({"kept": bool(src), "expires_at": src["expires_at"] if src else None})


# ------------------------------------------------------------------------------------------- webhook links
@router.get("/webhook-links")
def list_webhook_links(user=Depends(sec.require_user)):
    _guard()
    return cfg.ok({"items": ext.list_webhook_links(), "events": list(ext.CLOUD_EVENTS), "formats": list(ext.LINKABLE_FORMATS)})


@router.put("/webhook-links/{webhook_id}")
def link_webhook(webhook_id: str, body: WebhookLinkIn, user=Depends(sec.require_role("ADMIN"))):
    _guard()
    if not _WEBHOOK_ID.match(webhook_id):
        raise HTTPException(404, "webhook not found")
    try:
        out = ext.link_webhook(webhook_id, body.events, _who(user))
    except ext.ExtError as e:
        raise _bad(e)
    auditlog.record("cloud.webhook.linked", actor=user, detail={"webhook_id": webhook_id, "events": out["events"]})
    return cfg.ok(out)


@router.delete("/webhook-links/{webhook_id}")
def unlink_webhook(webhook_id: str, user=Depends(sec.require_role("ADMIN"))):
    _guard()
    if not _WEBHOOK_ID.match(webhook_id) or not ext.unlink_webhook(webhook_id):
        raise HTTPException(404, "link not found")
    auditlog.record("cloud.webhook.unlinked", actor=user, detail={"webhook_id": webhook_id})
    return cfg.ok({"deleted": True})


# ------------------------------------------------------------------------------------------------ asset links
@router.get("/scans/{scan_id}/assets")
def scan_assets(scan_id: str, user=Depends(sec.require_user)):
    _guard()
    return cfg.ok({"items": ext.links_for_scan(_scan(scan_id))})


@router.post("/scans/{scan_id}/assets", status_code=201)
def link_asset(scan_id: str, body: AssetLinkIn, user=Depends(sec.require_role("AUDITOR"))):
    _guard()
    if not _ASSET_ID.match(body.asset_id):
        raise HTTPException(400, "invalid asset id")
    try:
        out = ext.link_asset(_scan(scan_id), body.asset_id, _who(user))
    except ext.ExtError as e:
        raise _bad(e)
    auditlog.record("cloud.asset.linked", actor=user, detail={"scan_id": scan_id, "asset_id": body.asset_id})
    return cfg.ok(out)


@router.delete("/scans/{scan_id}/assets/{asset_id}")
def unlink_asset(scan_id: str, asset_id: str, user=Depends(sec.require_role("AUDITOR"))):
    _guard()
    if not _ASSET_ID.match(asset_id) or not ext.unlink_asset(_scan(scan_id), asset_id):
        raise HTTPException(404, "link not found")
    auditlog.record("cloud.asset.unlinked", actor=user, detail={"scan_id": scan_id, "asset_id": asset_id})
    return cfg.ok({"deleted": True})


@router.get("/assets/{asset_id}/scans")
def asset_scans(asset_id: str, user=Depends(sec.require_user)):
    _guard()
    if not _ASSET_ID.match(asset_id):
        raise HTTPException(404, "asset not found")
    return cfg.ok({"items": ext.links_for_asset(asset_id)})
