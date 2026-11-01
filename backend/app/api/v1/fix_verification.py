"""Lab verification of remediation templates (see app/services/fix_lab.py). APPROVER+ may record one: the label it
earns ("lab-verified") is what other users rely on when they decide to push a change."""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core import auditlog
from app.core import config as cfg
from app.core import security as sec
from app.services import fix_lab

router = APIRouter(prefix="/api/v1/remediation-verifications", tags=["remediation"])


class VerifyBody(BaseModel):
    control_id: str = Field(min_length=1, max_length=120)
    before_configuration_id: str = Field(min_length=1, max_length=64)
    after_configuration_id: str = Field(min_length=1, max_length=64)
    rollback_configuration_id: Optional[str] = Field(default=None, max_length=64)
    os_version: str = Field(default="", max_length=60)
    device_model: str = Field(default="", max_length=120)


@router.post("")
def verify(body: VerifyBody, user=Depends(sec.get_current_user)):
    try:
        rec = fix_lab.verify(control_id=body.control_id, before_id=body.before_configuration_id,
                             after_id=body.after_configuration_id, rollback_id=body.rollback_configuration_id,
                             os_version=body.os_version, device_model=body.device_model, verified_by=user.get("email"))
    except fix_lab.VerificationError as e:
        raise HTTPException(400, str(e))
    auditlog.record("remediation.lab_verification", actor=user,
                    detail={"verification_id": rec["verification_id"], "control_id": body.control_id, "status": rec["status"]})
    rec = {k: v for k, v in rec.items() if k != "evidence"}
    return cfg.ok(rec, "Verified" if rec["status"] == "VERIFIED" else "Not verified: " + str(rec["reason"]))


@router.get("")
def list_(control_id: Optional[str] = Query(default=None, max_length=120), limit: int = Query(default=100, ge=1, le=500)):
    return cfg.ok({"items": fix_lab.list_verifications(control_id, limit)})
