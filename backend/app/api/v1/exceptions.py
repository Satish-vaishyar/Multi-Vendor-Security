"""Risk-acceptance workflow: request (AUDITOR) -> approve/reject by a different APPROVER -> expires automatically."""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core import auditlog
from app.core import config as cfg
from app.core import risk_exceptions as rx
from app.core import security as sec

router = APIRouter(prefix="/api/v1/exceptions", tags=["exceptions"])


class ExcBody(BaseModel):
    asset_id: str = Field(min_length=1, max_length=100)
    finding_key: str = Field(min_length=1, max_length=300)
    reason: str = Field(min_length=1, max_length=2000)
    days: int = 30


class Decision(BaseModel):
    comment: str = Field(default="", max_length=1000)


def _who(user) -> str:
    return str(user.get("email") or user.get("id") or "unknown")


@router.get("")
def list_exceptions(status: Optional[str] = None, asset_id: Optional[str] = None):
    return cfg.ok({"items": rx.list_all(status, asset_id), "max_days": cfg.EXCEPTION_MAX_DAYS})


@router.post("", status_code=201)
def request_exception(body: ExcBody, user=Depends(sec.require_user)):
    try:
        e = rx.request(body.asset_id, body.finding_key, body.reason, body.days, _who(user))
    except rx.ExceptionError as ex:
        raise HTTPException(400, str(ex))
    auditlog.record("exception.requested", actor=user, detail={"exception_id": e["exception_id"], "asset_id": body.asset_id,
                                                                "finding_key": body.finding_key, "days": body.days})
    return cfg.ok(e, "Exception requested - a different approver must approve it")


def _decide(exception_id: str, decision: str, body: Decision, user):
    try:
        e = rx.decide(exception_id, decision, _who(user), body.comment)
    except LookupError:
        raise HTTPException(404, "Exception not found")
    except rx.Forbidden as ex:
        raise HTTPException(403, str(ex))
    except rx.ExceptionError as ex:
        raise HTTPException(409, str(ex))
    auditlog.record(f"exception.{decision.lower()}", actor=user, detail={"exception_id": exception_id, "comment": body.comment[:200]})
    return cfg.ok(e)


@router.post("/{exception_id}/approve")
def approve(exception_id: str, body: Decision = Decision(), user=Depends(sec.require_user)):
    return _decide(exception_id, "APPROVED", body, user)


@router.post("/{exception_id}/reject")
def reject(exception_id: str, body: Decision = Decision(), user=Depends(sec.require_user)):
    return _decide(exception_id, "REJECTED", body, user)


@router.post("/{exception_id}/revoke")
def revoke(exception_id: str, body: Decision = Decision(), user=Depends(sec.require_user)):
    return _decide(exception_id, "REVOKED", body, user)
