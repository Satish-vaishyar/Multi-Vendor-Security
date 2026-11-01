"""Administration (ADMIN role, enforced by the RBAC matrix): users + audit log. Tenant-scoped."""
from __future__ import annotations
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.core import auditlog
from app.core import config as cfg
from app.core import db as dbmod
from app.core import rbac
from app.core import security as sec
from app.core import tenancy

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


class NewUser(BaseModel):
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=256)
    role: str = rbac.VIEWER
    must_change_password: bool = True


class UserPatch(BaseModel):
    role: Optional[str] = None
    disabled: Optional[bool] = None
    new_password: Optional[str] = Field(default=None, max_length=256)


def _own_user(user_id: str) -> dict:
    u = sec._user_by_id(user_id)
    if not u or u.get("org_id") != tenancy.current_org():
        raise HTTPException(404, "User not found")
    return u


@router.get("/users")
def list_users():
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(f"SELECT {sec._USER_COLS} FROM users WHERE org_id=%s ORDER BY created_at", (tenancy.current_org(),))
        rows = [sec._row_to_user(r) for r in cur.fetchall()]
    items = [{**sec.public_user(u), "disabled": bool(u["disabled"])} for u in rows]
    return cfg.ok({"items": items, "total": len(items)})


@router.post("/users")
def create_user(body: NewUser):
    try:
        u = sec.create_user(body.email, body.name, body.password, body.role,
                            org_id=tenancy.current_org(), must_change=body.must_change_password)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return cfg.ok(sec.public_user(u), "User created")


@router.patch("/users/{user_id}")
def patch_user(user_id: str, body: UserPatch, actor=Depends(sec.require_user)):
    u = _own_user(user_id)
    sets, vals = [], []
    if body.role is not None:
        role = body.role.upper()
        if role not in rbac.ROLES:
            raise HTTPException(400, f"role must be one of {rbac.ROLES}")
        if u["id"] == actor["id"] and role != rbac.ADMIN:
            raise HTTPException(400, "You cannot demote yourself")
        sets.append("role=%s")
        vals.append(role)
        sets.append("token_version=token_version+1")  # force re-login with the new role
    if body.disabled is not None:
        if u["id"] == actor["id"] and body.disabled:
            raise HTTPException(400, "You cannot disable yourself")
        sets.append("disabled=%s")
        vals.append(body.disabled)
        if body.disabled:
            sets.append("token_version=token_version+1")
    if body.new_password is not None:
        probs = sec.password_problems(body.new_password, u["email"])
        if probs:
            raise HTTPException(400, "Weak password: " + "; ".join(probs))
        sets += ["password_hash=%s", "must_change_password=true", "token_version=token_version+1",
                 "failed_attempts=0", "locked_until=NULL"]
        vals.append(sec._hash(body.new_password))
    if not sets:
        raise HTTPException(400, "Nothing to update")
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=%s AND org_id=%s",
                    vals + [user_id, tenancy.current_org()])
    fresh = sec._user_by_id(user_id)
    assert fresh is not None
    return cfg.ok({**sec.public_user(fresh), "disabled": bool(fresh["disabled"])}, "User updated")


@router.post("/users/{user_id}/mfa-reset")
def reset_mfa(user_id: str, request: Request, actor=Depends(sec.require_user)):
    """Admin recovery for a user who lost their device and recovery codes (their sessions are revoked)."""
    from app.core import mfa
    u = _own_user(user_id)
    mfa.disable(u["id"])
    auditlog.record("admin.mfa_reset", actor=actor, method="POST", path=request.url.path, status=200,
                    detail={"target": u["id"]})
    return cfg.ok({"user_id": u["id"], "mfa_enabled": False}, "MFA reset; the user must enrol again")


@router.get("/audit-log")
def audit_log(request: Request, limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
              action: Optional[str] = None, actor_id: Optional[str] = None):
    clauses, vals = ["org_id=%s"], [tenancy.current_org()]
    if action:
        clauses.append("action=%s")
        vals.append(action)
    if actor_id:
        clauses.append("actor_id=%s")
        vals.append(actor_id)
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("SELECT id, ts, actor_id, actor_email, role, action, method, path, status, ip, request_id, detail "
                    f"FROM audit_log WHERE {' AND '.join(clauses)} ORDER BY id DESC LIMIT %s OFFSET %s",
                    vals + [limit, offset])
        cols = [d[0] for d in cur.description]  # type: ignore[union-attr]
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    for r in rows:
        r["ts"] = r["ts"].isoformat()
    return cfg.ok({"items": rows, "limit": limit, "offset": offset})


@router.post("/retention/run")
def run_retention(dry_run: bool = Query(True, description="report what would be purged; pass false to delete")):
    """Apply the data-retention policy to the CALLER'S organisation now (by age only). Defaults to a dry run for safety.
    The platform-wide purge runs from the worker / CLI, never from a tenant-facing endpoint."""
    from app.services import retention
    return cfg.ok(retention.run(dry_run=dry_run, org_id=tenancy.current_org()), "dry run" if dry_run else "retention applied")
