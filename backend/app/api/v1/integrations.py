"""Integrations (ADMIN): outbound webhooks - signed, retried, logged. Secrets are shown once."""
from __future__ import annotations
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core import config as cfg
from app.core import jobs, webhooks
from app.core import security as sec

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])


class HookBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=8, max_length=2000)
    events: List[str] = ["audit.completed", "finding.new_critical_high", "job.failed"]
    format: str = "json"
    auth_header: Optional[str] = Field(default=None, max_length=2000, repr=False)   # "Header-Name: token"; stored encrypted, never returned


class HookPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    url: Optional[str] = Field(default=None, min_length=8, max_length=2000)
    events: Optional[List[str]] = None
    format: Optional[str] = None
    enabled: Optional[bool] = None
    auth_header: Optional[str] = Field(default=None, max_length=2000, repr=False)   # "" clears it


@router.get("/webhooks/catalog")
def catalog():
    return cfg.ok({"events": list(webhooks.EVENTS), "formats": list(webhooks.FORMATS),
                   "signature": "X-Signature-256: sha256=HMAC_SHA256(secret, f'{X-Timestamp}.{raw_body}')"})


@router.get("/webhooks")
def list_hooks():
    return cfg.ok({"items": webhooks.list_all()})


@router.post("/webhooks", status_code=201)
def create_hook(body: HookBody, user=Depends(sec.require_user)):
    try:
        h = webhooks.create(body.name, body.url, body.events, body.format, user.get("email") or user.get("id"),
                          auth_header=body.auth_header)
    except webhooks.WebhookError as e:
        raise HTTPException(400, str(e))
    return cfg.ok(h, "Webhook created. Copy the secret now - it will not be shown again.")


@router.get("/webhooks/{webhook_id}")
def get_hook(webhook_id: str):
    h = webhooks.get(webhook_id)
    if not h:
        raise HTTPException(404, "Webhook not found")
    return cfg.ok(h)


@router.patch("/webhooks/{webhook_id}")
def patch_hook(webhook_id: str, body: HookPatch):
    try:
        h = webhooks.update(webhook_id, name=body.name, url=body.url, events=body.events, fmt=body.format, enabled=body.enabled,
                          auth_header=body.auth_header)
    except webhooks.WebhookError as e:
        raise HTTPException(400, str(e))
    if not h:
        raise HTTPException(404, "Webhook not found")
    return cfg.ok(h, "Webhook updated")


@router.delete("/webhooks/{webhook_id}")
def delete_hook(webhook_id: str):
    if not webhooks.delete(webhook_id):
        raise HTTPException(404, "Webhook not found")
    return cfg.ok({"webhook_id": webhook_id}, "Webhook deleted")


@router.post("/webhooks/{webhook_id}/rotate-secret")
def rotate(webhook_id: str):
    s = webhooks.rotate_secret(webhook_id)
    if not s:
        raise HTTPException(404, "Webhook not found")
    return cfg.ok({"webhook_id": webhook_id, "secret": s}, "Secret rotated. Copy it now - it will not be shown again.")


@router.post("/webhooks/{webhook_id}/test", status_code=202)
def test_hook(webhook_id: str, user=Depends(sec.require_user)):
    h = webhooks.get(webhook_id)
    if not h:
        raise HTTPException(404, "Webhook not found")
    try:
        jid = jobs.enqueue("webhook", {"webhook_id": webhook_id, "event": "ping", "data": {"message": "test delivery"}},
                           created_by=user.get("email") or user.get("id"), max_attempts=1)
    except jobs.QueueFull as e:
        raise HTTPException(429, str(e))
    return cfg.ok({"job_id": jid}, "Test delivery queued")


@router.get("/webhooks/{webhook_id}/deliveries")
def deliveries(webhook_id: str, limit: int = Query(50, ge=1, le=200)):
    if not webhooks.get(webhook_id):
        raise HTTPException(404, "Webhook not found")
    return cfg.ok({"items": webhooks.deliveries(webhook_id, limit)})
