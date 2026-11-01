"""Live collection: credential vault (ADMIN), per-asset collection target (ADMIN), and a "collect now" job (AUDITOR).

Why the split: a credential is only ever sent to the host whose key fingerprint is pinned on the target, and the target
decides which host that is. Whoever can edit targets could aim a stored credential at a machine they control, so
targets and credentials are ADMIN-only; running a collection against an already-approved target is a normal AUDITOR job.
"""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core import collector, auditlog
from app.core import config as cfg
from app.core import jobs
from app.core import security as sec
from app.services import collection

router = APIRouter(prefix="/api/v1", tags=["collection"])


class CredentialBody(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    username: str = Field(min_length=1, max_length=120)
    secret: str = Field(min_length=1, max_length=16384, description="password, or a PEM private key when auth_type=key")
    auth_type: str = Field(default="password", pattern="^(password|key)$")


class TargetBody(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    profile: str = Field(min_length=1, max_length=40)
    credential_id: Optional[str] = Field(default=None, max_length=40)
    host_key: str = Field(min_length=10, max_length=120, description="pinned SHA256 fingerprint from scan-host-key")


class ScanBody(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)


class CollectBody(BaseModel):
    audit: bool = True


@router.get("/collection/profiles")
def profiles():
    return cfg.ok([{"key": p.key, "label": p.label, "commands": p.commands} for p in collector.PROFILES.values()])


@router.get("/collection/credentials")
def list_credentials():
    return cfg.ok({"items": collection.list_credentials()})


@router.post("/collection/credentials")
def create_credential(body: CredentialBody, user=Depends(sec.get_current_user)):
    try:
        out = collection.create_credential(body.name, body.username, body.secret, body.auth_type, user.get("email"))
    except ValueError as e:
        raise HTTPException(400, str(e))
    auditlog.record("collection.credential_created", actor=user, detail={"credential_id": out["credential_id"], "name": body.name})
    return cfg.ok(out, "Credential stored (encrypted); it can not be read back")


@router.delete("/collection/credentials/{credential_id}")
def delete_credential(credential_id: str, user=Depends(sec.get_current_user)):
    if not collection.delete_credential(credential_id):
        raise HTTPException(404, "Credential not found")
    auditlog.record("collection.credential_deleted", actor=user, detail={"credential_id": credential_id})
    return cfg.ok({"deleted": True})


@router.post("/assets/{asset_id}/collection/scan-host-key")
def scan_host_key(asset_id: str, body: ScanBody):
    """Fetch the device's SSH host-key fingerprint (no authentication). The administrator confirms it out of band."""
    try:
        return cfg.ok({"host": body.host, "port": body.port, "fingerprint": collector.scan_host_key(body.host, body.port)})
    except collector.CollectError as e:
        raise HTTPException(400, str(e))


@router.put("/assets/{asset_id}/collection")
def set_target(asset_id: str, body: TargetBody, user=Depends(sec.get_current_user)):
    try:
        out = collection.set_target(asset_id, body.host, body.port, body.profile, body.credential_id, body.host_key)
    except LookupError:
        raise HTTPException(404, "Asset not found")
    except ValueError as e:
        raise HTTPException(400, str(e))
    auditlog.record("collection.target_set", actor=user, detail={"asset_id": asset_id, "host": body.host, "port": body.port})
    return cfg.ok(out)


@router.get("/assets/{asset_id}/collection")
def get_target(asset_id: str):
    t = collection.get_target(asset_id)
    if not t:
        raise HTTPException(404, "No collection target for this asset")
    return cfg.ok(t)


@router.post("/assets/{asset_id}/collect")
def collect(asset_id: str, body: CollectBody, user=Depends(sec.get_current_user)):
    t = collection.get_target(asset_id)
    if not t or not t["credential_id"] or not t["host_key"]:
        raise HTTPException(400, "Configure the target (host, credential, pinned host key) first")
    try:
        job_id = jobs.enqueue("collect", {"asset_id": asset_id, "audit": body.audit}, created_by=user.get("email"))
    except jobs.QueueFull as e:
        raise HTTPException(429, str(e))
    auditlog.record("collection.requested", actor=user, detail={"asset_id": asset_id, "job_id": job_id})
    return cfg.ok({"job_id": job_id, "status": "QUEUED"}, "Collection queued")
