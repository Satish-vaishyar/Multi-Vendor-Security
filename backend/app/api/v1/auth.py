"""Auth: login / logout / me / change-password (api.md §4)."""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app.core import auditlog
from app.core import config as cfg
from app.core import db as dbmod
from app.core import oidc
from app.core import security as sec

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginBody(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)
    otp: str = Field(default="", max_length=32)          # TOTP code or a recovery code (only when MFA is enabled)


class MfaCode(BaseModel):
    code: str = Field(min_length=1, max_length=32)


class MfaDisable(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    code: str = Field(min_length=1, max_length=32)


class ChangePasswordBody(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/login")
def login(body: LoginBody, request: Request, response: Response):
    ip = _ip(request)
    rid = request.headers.get("X-Request-ID", "")
    try:
        user = sec.authenticate(body.email, body.password, ip, body.otp or None)
    except sec.AuthFailure as f:
        auditlog.record("auth.login_failed", method="POST", path=request.url.path, status=f.status_code,
                        ip=ip, request_id=rid, detail={"email": body.email[:254], "reason": f.reason})
        raise HTTPException(status_code=f.status_code, detail=f.detail)
    if oidc.enabled() and cfg.SSO_ONLY and user["role"] != "ADMIN":      # admins keep a break-glass password login
        auditlog.record("auth.login_failed", method="POST", path=request.url.path, status=403, ip=ip, request_id=rid,
                        detail={"email": body.email[:254], "reason": "sso_only"})
        raise HTTPException(status_code=403, detail="Password login is disabled; use single sign-on")
    auditlog.record("auth.login", actor=user, method="POST", path=request.url.path, status=200,
                    ip=ip, request_id=rid)
    return cfg.ok(sec.set_session_cookies(response, request, sec.make_token(user)), "Login successful")


@router.get("/me", dependencies=[Depends(sec.bind_tenant)])
def me(user=Depends(sec.get_current_user)):
    return cfg.ok(sec.public_user(user))


@router.post("/logout", dependencies=[Depends(sec.bind_tenant)])
def logout(request: Request, response: Response, user=Depends(sec.get_current_user)):
    sec.clear_session_cookies(response)
    sec.revoke_token(user["_jti"], user["_exp"])
    auditlog.record("auth.logout", actor=user, method="POST", path=request.url.path, status=200, ip=_ip(request))
    return cfg.ok({"revoked": True}, "Logged out")


@router.post("/change-password", dependencies=[Depends(sec.bind_tenant)])
def change_password(body: ChangePasswordBody, request: Request, response: Response, user=Depends(sec.get_current_user)):
    sec.assert_not_locked(user["id"])               # a stolen session must not be able to brute-force the current password
    if not sec._verify(body.current_password, user["password_hash"]):
        sec.register_failure(user["id"])
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    problems = sec.password_problems(body.new_password, user["email"])
    if problems:
        raise HTTPException(status_code=400, detail="Weak password: " + "; ".join(problems))
    if body.new_password == body.current_password:
        raise HTTPException(status_code=400, detail="New password must differ from the current one")
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("UPDATE users SET password_hash=%s, token_version=token_version+1, "
                    "must_change_password=false, failed_attempts=0, locked_until=NULL WHERE id=%s",
                    (sec._hash(body.new_password), user["id"]))
    fresh = sec._user_by_id(user["id"])
    assert fresh is not None
    auditlog.record("auth.password_changed", actor=user, method="POST", path=request.url.path, status=200,
                    ip=_ip(request))
    return cfg.ok(sec.set_session_cookies(response, request, sec.make_token(fresh)), "Password changed; all other sessions were signed out")


# ------------------------------------------------------------------ MFA (TOTP)
@router.get("/mfa", dependencies=[Depends(sec.bind_tenant)])
def mfa_status(user=Depends(sec.get_current_user)):
    from app.core import mfa
    return cfg.ok(mfa.status(user["id"]))


@router.post("/mfa/setup", dependencies=[Depends(sec.bind_tenant)])
def mfa_setup(request: Request, user=Depends(sec.get_current_user)):
    """Start enrolment: returns the secret + otpauth URI (scan as QR). MFA is not active until /mfa/enable succeeds."""
    from app.core import mfa
    if user.get("mfa_enabled"):
        raise HTTPException(400, "MFA is already enabled; disable it first to re-enrol")
    auditlog.record("auth.mfa_setup", actor=user, method="POST", path=request.url.path, status=200, ip=_ip(request))
    return cfg.ok(mfa.begin_enrolment(user["id"], user["email"]), "Scan the QR code, then confirm with a code")


@router.post("/mfa/enable", dependencies=[Depends(sec.bind_tenant)])
def mfa_enable(body: MfaCode, request: Request, response: Response, user=Depends(sec.get_current_user)):
    from app.core import mfa
    sec.assert_not_locked(user["id"])               # code guesses share the login lockout counter
    codes = mfa.confirm_enrolment(user["id"], body.code)
    if codes is None:
        sec.register_failure(user["id"])
        raise HTTPException(400, "Invalid code (or enrolment not started)")
    auditlog.record("auth.mfa_enabled", actor=user, method="POST", path=request.url.path, status=200, ip=_ip(request))
    fresh = sec._user_by_id(user["id"])
    assert fresh is not None
    return cfg.ok({"recovery_codes": codes, **sec.set_session_cookies(response, request, sec.make_token(fresh))},
                  "MFA enabled. Store the recovery codes safely - they are shown only once.")


@router.post("/mfa/disable", dependencies=[Depends(sec.bind_tenant)])
def mfa_disable(body: MfaDisable, request: Request, response: Response, user=Depends(sec.get_current_user)):
    from app.core import mfa
    sec.assert_not_locked(user["id"])               # a stolen session must not be able to brute-force the 6-digit code
    if not sec._verify(body.password, user["password_hash"]) or not mfa.check(user["id"], body.code):
        sec.register_failure(user["id"])
        raise HTTPException(400, "Password or MFA code is incorrect")
    mfa.disable(user["id"])
    auditlog.record("auth.mfa_disabled", actor=user, method="POST", path=request.url.path, status=200, ip=_ip(request))
    fresh = sec._user_by_id(user["id"])
    assert fresh is not None
    return cfg.ok(sec.set_session_cookies(response, request, sec.make_token(fresh)), "MFA disabled; other sessions were signed out")
