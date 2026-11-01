"""OIDC single sign-on endpoints (public; they ARE the login). See app/core/oidc.py for the security model."""
from __future__ import annotations
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from app.core import auditlog
from app.core import config as cfg
from app.core import oidc
from app.core import security as sec

router = APIRouter(prefix="/api/v1/auth/sso", tags=["sso"])


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _back(path: str, **q: str) -> str:
    base = cfg.OIDC_FRONTEND_URL.rstrip("/")
    return f"{base}{path}" + (f"?{urlencode(q)}" if q else "")


def _fail(request: Request, reason: str) -> RedirectResponse:
    # the browser only ever sees a generic code; the real reason is in the audit log
    auditlog.record("auth.sso_failed", method="GET", path=request.url.path, status=302, ip=_ip(request),
                    detail={"reason": reason})
    r = RedirectResponse(_back("/login", sso_error="1"), status_code=303)
    r.delete_cookie(oidc.TX_COOKIE, path="/api/v1/auth/sso")
    return r


@router.get("/config")
def config():
    return cfg.ok(oidc.public_config())


@router.get("/login")
def login(request: Request):
    if not oidc.enabled():
        raise HTTPException(status_code=404, detail="Single sign-on is not configured")
    if sec._ip_throttled(_ip(request)):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again in a minute.")
    try:
        url, tx = oidc.begin()
    except oidc.SSOError as e:
        return _fail(request, e.reason)
    r = RedirectResponse(url, status_code=303)
    # Lax (not Strict): the IdP sends the browser back with a cross-site top-level GET, which Strict would drop
    r.set_cookie(oidc.TX_COOKIE, tx, max_age=oidc.TX_TTL, httponly=True, samesite="lax",
                 secure=cfg.ENV == "production", path="/api/v1/auth/sso")
    return r


@router.get("/callback")
def callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if not oidc.enabled():
        raise HTTPException(status_code=404, detail="Single sign-on is not configured")
    if error:
        return _fail(request, "idp_error:" + error[:60])
    try:
        claims = oidc.complete(code, state, request.cookies.get(oidc.TX_COOKIE))
        user = oidc.resolve_user(claims)
    except oidc.SSOError as e:
        return _fail(request, e.reason)
    except Exception:                                   # never leak a stack trace through a login redirect
        return _fail(request, "internal_error")
    resp = RedirectResponse(_back("/sso/complete"), status_code=303)
    sec.set_session_cookies(resp, request, sec.make_token(user), force=True)
    resp.delete_cookie(oidc.TX_COOKIE, path="/api/v1/auth/sso")
    auditlog.record("auth.sso_login", actor=user, method="GET", path=request.url.path, status=303, ip=_ip(request),
                    detail={"issuer": cfg.OIDC_ISSUER, "role": user["role"]})
    return resp
