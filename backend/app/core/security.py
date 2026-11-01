"""Authentication, session control and RBAC enforcement.

Highlights
  * PBKDF2-HMAC-SHA256 password hashes (600k iterations, transparent upgrade on login)
  * per-account lockout + per-IP login throttling, uniform error for unknown users
  * short-lived JWTs carrying jti + token_version; logout revokes the jti,
    password change/reset bumps token_version (kills every older token)
  * every /api/v1 request: authenticate -> bind tenant -> enforce the RBAC matrix
  * REQUIRE_AUTH=false (development only) maps requests to a dev admin
"""
from __future__ import annotations
import functools
import hashlib
import hmac as _hmac
import logging
import os as _os
import re
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, List, Optional

import jwt
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core import config as cfg
from app.core import db as dbmod
from app.core import persist as db
from app.core import rbac, tenancy

log = logging.getLogger("sih26155")
_bearer = HTTPBearer(auto_error=False)

_USER_COLS = ("id, email, name, password_hash, role, org_id, failed_attempts, locked_until, "
              "token_version, must_change_password, disabled, mfa_enabled")
_USER_KEYS = [c.strip() for c in _USER_COLS.split(",")]


def _system(fn):
    """Identity resolution is inherently cross-tenant (the caller's org is not known until the user row is found), so
    it runs in the explicit system scope. Everything after authentication is bound to the caller's own org."""
    @functools.wraps(fn)
    def wrapper(*a, **k):
        with tenancy.unscoped():
            return fn(*a, **k)
    return wrapper


# ------------------------------------------------------------------ passwords
def _hash(password: str, iterations: Optional[int] = None) -> str:
    iters = iterations or cfg.PASSWORD_HASH_ITERATIONS
    salt = _os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters)
    return f"pbkdf2${iters}${salt.hex()}${dk.hex()}"


def _verify(password: str, stored: str) -> bool:
    try:
        _, iters, salt_h, dk_h = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_h), int(iters))
        return _hmac.compare_digest(dk.hex(), dk_h)
    except Exception:
        return False


def _needs_rehash(stored: str) -> bool:
    try:
        return int(stored.split("$")[1]) < cfg.PASSWORD_HASH_ITERATIONS
    except Exception:
        return True


_COMMON = {"password", "password1", "password123", "123456789012", "qwertyuiop12", "admin123456",
           "administrator", "letmein12345", "welcome12345", "changeme1234"}


def password_problems(password: str, email: str = "") -> List[str]:
    """Policy: length, mixed character classes, not trivially guessable."""
    p: List[str] = []
    try:
        password.encode("utf-8")
    except UnicodeEncodeError:
        return ["contains characters that cannot be encoded (lone surrogates)"]
    if len(password) < cfg.PASSWORD_MIN_LENGTH:
        p.append(f"at least {cfg.PASSWORD_MIN_LENGTH} characters")
    classes = sum(bool(re.search(rx, password)) for rx in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if classes < 3:
        p.append("use at least 3 of: lowercase, uppercase, digits, symbols")
    if password.lower() in _COMMON or (email and email.split("@")[0].lower() in password.lower()
                                       and len(email.split("@")[0]) >= 4):
        p.append("too easy to guess")
    return p


# --------------------------------------------------------------------- users
def _row_to_user(row) -> Dict[str, Any]:
    return dict(zip(_USER_KEYS, row))


@_system
def _user_by_email(email: str) -> Optional[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(f"SELECT {_USER_COLS} FROM users WHERE lower(email::text)=lower(%s)", (email,))
        r = cur.fetchone()
    return _row_to_user(r) if r else None


@_system
def _user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(f"SELECT {_USER_COLS} FROM users WHERE id=%s", (user_id,))
        r = cur.fetchone()
    return _row_to_user(r) if r else None


def public_user(u: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": u["id"], "name": u["name"], "email": u["email"], "role": u["role"],
            "org_id": u.get("org_id") or cfg.DEFAULT_ORG_ID,
            "must_change_password": bool(u.get("must_change_password")),
            "mfa_enabled": bool(u.get("mfa_enabled")),
            "mfa_enrollment_required": (not u.get("mfa_enabled")) and str(u.get("role", "")).upper() in cfg.MFA_REQUIRED_ROLES}


def create_user(email: str, name: str, password: str, role: str = rbac.VIEWER,
                org_id: Optional[str] = None, must_change: bool = False,
                enforce_policy: bool = True) -> Dict[str, Any]:
    role = role.upper()
    if role not in rbac.ROLES:
        raise ValueError(f"role must be one of {rbac.ROLES}")
    if enforce_policy:
        probs = password_problems(password, email)
        if probs:
            raise ValueError("weak password: " + "; ".join(probs))
    if _user_by_email(email):
        raise ValueError("a user with this e-mail already exists")
    rec = {"id": "USR-" + uuid.uuid4().hex[:10].upper(), "name": name, "email": email.lower(),
           "password_hash": _hash(password), "role": role, "failed_attempts": 0,
           "token_version": 0, "must_change_password": must_change, "disabled": False,
           "org_id": org_id or cfg.DEFAULT_ORG_ID}
    with tenancy.unscoped():
        db.save("users", rec)
    return rec


_bootstrapped = False


@_system
def ensure_bootstrap_admin() -> bool:
    """Create the first admin if the users table is empty. Never raises."""
    global _bootstrapped
    if _bootstrapped:
        return True
    try:
        with dbmod.get_conn() as conn:
            cur = conn.cursor()  # type: ignore[attr-defined]
            cur.execute("SELECT count(*) FROM users")
            (n,) = cur.fetchone()
        if n == 0:
            create_user(cfg.ADMIN_EMAIL, "Admin", cfg.ADMIN_PASSWORD, rbac.ADMIN,
                        must_change=cfg.ADMIN_PASSWORD.lower() in cfg._WEAK_ADMIN_PASSWORDS,
                        enforce_policy=False)
            log.info("bootstrap admin created: %s", cfg.ADMIN_EMAIL)
        _bootstrapped = True
        return True
    except Exception as e:
        log.warning("bootstrap admin skipped (db unreachable): %s", e)
        return False


# ------------------------------------------------------- login protections
_ip_hits: Dict[str, Deque[float]] = defaultdict(deque)
_ip_lock = threading.Lock()


def _ip_throttled(ip: str) -> bool:
    """Sliding 60 s window per client IP (per process; the account lockout is DB-wide)."""
    now = time.monotonic()
    with _ip_lock:
        q = _ip_hits[ip]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= cfg.LOGIN_IP_MAX_PER_MINUTE:
            return True
        q.append(now)
        return False


def reset_throttle() -> None:
    with _ip_lock:
        _ip_hits.clear()


_dummy_cache: Dict[int, str] = {}


def _dummy_hash() -> str:
    """Hash with the SAME cost as real accounts, so 'unknown e-mail' and 'wrong password' take equally long
    (a cheap dummy hash lets an attacker enumerate accounts by response time)."""
    it = int(cfg.PASSWORD_HASH_ITERATIONS)
    h = _dummy_cache.get(it)
    if h is None:
        h = _dummy_cache[it] = _hash("dummy-password-for-timing", it)
    return h


@_system
def assert_not_locked(user_id: str) -> None:
    """429 while the account lockout is active (used by the second-factor endpoints that take a code)."""
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("SELECT locked_until > now() FROM users WHERE id=%s", (user_id,))
        r = cur.fetchone()
    if r and r[0]:
        raise HTTPException(status_code=429, detail="Account temporarily locked. Try again later.")


@_system
def register_failure(user_id: str) -> None:
    """Count a failed secret/code guess toward the account lockout (same counter as failed logins)."""
    with dbmod.get_conn() as conn:
        conn.cursor().execute(  # type: ignore[attr-defined]
            "UPDATE users SET failed_attempts=failed_attempts+1, locked_until=CASE WHEN "
            "failed_attempts+1>=%s THEN now()+make_interval(mins=>%s) ELSE locked_until END WHERE id=%s",
            (cfg.LOGIN_MAX_ATTEMPTS, cfg.LOGIN_LOCKOUT_MINUTES, user_id))


class AuthFailure(Exception):
    def __init__(self, status_code: int, detail: str, reason: str):
        self.status_code, self.detail, self.reason = status_code, detail, reason


@_system
def authenticate(email: str, password: str, ip: str = "unknown", otp: Optional[str] = None) -> Dict[str, Any]:
    """Return the user or raise AuthFailure. Never reveals whether the e-mail exists."""
    if _ip_throttled(ip):
        raise AuthFailure(429, "Too many login attempts. Try again in a minute.", "ip_throttled")
    ensure_bootstrap_admin()
    try:
        u = _user_by_email(email)
    except Exception:
        raise AuthFailure(503, "Service unavailable", "db_error")
    now = datetime.now(timezone.utc)
    if u and u.get("locked_until") and u["locked_until"] > now:
        _verify(password, _dummy_hash())  # keep timing flat
        raise AuthFailure(429, "Account temporarily locked. Try again later.", "locked")
    ok = _verify(password, u["password_hash"] if u else _dummy_hash()) and u is not None
    if not ok or (u and u.get("disabled")):
        if u:
            with dbmod.get_conn() as conn:
                cur = conn.cursor()  # type: ignore[attr-defined]
                cur.execute(
                    "UPDATE users SET failed_attempts=failed_attempts+1, locked_until=CASE WHEN "
                    "failed_attempts+1>=%s THEN now()+make_interval(mins=>%s) ELSE locked_until END "
                    "WHERE id=%s", (cfg.LOGIN_MAX_ATTEMPTS, cfg.LOGIN_LOCKOUT_MINUTES, u["id"]))
        raise AuthFailure(401, "Invalid credentials", "bad_credentials" if not (u and u.get("disabled")) else "disabled")
    assert u is not None
    if u.get("mfa_enabled"):
        from app.core import mfa
        if not otp:
            # password was right: tell the client to ask for the second factor (does not count as a failure)
            raise AuthFailure(401, "MFA code required", "mfa_required")
        if not mfa.check(u["id"], otp):
            register_failure(u["id"])
            raise AuthFailure(401, "Invalid MFA code", "bad_mfa")
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        if _needs_rehash(u["password_hash"]):
            cur.execute("UPDATE users SET password_hash=%s WHERE id=%s", (_hash(password), u["id"]))
        cur.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=%s", (u["id"],))
    return u


# --------------------------------------------------------------------- tokens
def make_token(user: Dict[str, Any]) -> Dict[str, Any]:
    now = int(time.time())
    exp = now + cfg.JWT_EXPIRE_MINUTES * 60
    payload = {"sub": user["id"], "email": user["email"], "role": user["role"],
               "org": user.get("org_id") or cfg.DEFAULT_ORG_ID, "tv": int(user.get("token_version") or 0),
               "jti": uuid.uuid4().hex, "iat": now, "exp": exp}
    token = jwt.encode(payload, cfg.JWT_SECRET, algorithm=cfg.JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "expires_in": cfg.JWT_EXPIRE_MINUTES * 60,
            "user": public_user(user)}


def revoke_token(jti: str, exp: int) -> None:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("DELETE FROM revoked_tokens WHERE expires_at < now()")
        cur.execute("INSERT INTO revoked_tokens (jti, expires_at) VALUES (%s, to_timestamp(%s)) "
                    "ON CONFLICT (jti) DO NOTHING", (jti, exp))


def _is_revoked(jti: str) -> bool:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("SELECT 1 FROM revoked_tokens WHERE jti=%s", (jti,))
        return cur.fetchone() is not None


def decode_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, cfg.JWT_SECRET, algorithms=[cfg.JWT_ALGORITHM],
                          options={"require": ["exp", "sub", "jti"]})
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


_SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def csrf_for(jti: str) -> str:
    """CSRF token bound to the session (HMAC of its jti under the server secret). A plain random double-submit
    value can be planted by a sibling sub-domain (cookie tossing); this one cannot be forged without the secret."""
    return _hmac.new(cfg.JWT_SECRET.encode(), b"csrf:" + jti.encode(), hashlib.sha256).hexdigest()


def _cookie_token(request: Request) -> Optional[str]:
    """Session token from the httpOnly cookie. Unsafe methods must prove same-origin intent (signed double-submit CSRF)."""
    tok = request.cookies.get(cfg.SESSION_COOKIE)
    if not tok:
        return None
    if request.method.upper() not in _SAFE_METHODS:
        sent, want = request.headers.get("X-CSRF-Token", ""), request.cookies.get(cfg.CSRF_COOKIE, "")
        if not sent or not want or not secrets.compare_digest(sent, want):
            raise HTTPException(status_code=403, detail="CSRF token missing or invalid")
        expected = csrf_for(str(decode_token(tok)["jti"]))
        if not secrets.compare_digest(sent, expected):
            raise HTTPException(status_code=403, detail="CSRF token missing or invalid")
    return tok


def set_session_cookies(response: Response, request: Request, tok: Dict[str, Any], force: bool = False) -> Dict[str, Any]:
    """Cookie mode (X-Auth-Mode: cookie, or force=True for the SSO redirect): put the JWT in an httpOnly cookie and
    keep it OUT of the JSON body."""
    if not force and request.headers.get("X-Auth-Mode", "").lower() != "cookie":
        return tok
    secure = cfg.ENV == "production" or request.headers.get("X-Forwarded-Proto", request.url.scheme) == "https"
    age = int(tok.get("expires_in") or cfg.JWT_EXPIRE_MINUTES * 60)
    response.set_cookie(cfg.SESSION_COOKIE, tok["access_token"], max_age=age, httponly=True, secure=secure,
                        samesite="strict", path="/api")
    jti = str(jwt.decode(tok["access_token"], options={"verify_signature": False})["jti"])   # our own fresh token
    response.set_cookie(cfg.CSRF_COOKIE, csrf_for(jti), max_age=age, httponly=False, secure=secure,
                        samesite="strict", path="/")
    return {**tok, "access_token": ""}


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(cfg.SESSION_COOKIE, path="/api")
    response.delete_cookie(cfg.CSRF_COOKIE, path="/")


def get_current_user(request: Request,
                     creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)) -> Dict[str, Any]:
    token = creds.credentials if creds else _cookie_token(request)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    payload = decode_token(token)
    try:
        if _is_revoked(payload["jti"]):
            raise HTTPException(status_code=401, detail="Token revoked")
        user = _user_by_id(payload["sub"])
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if not user or user.get("disabled"):
        raise HTTPException(status_code=401, detail="User not found")
    if int(payload.get("tv", 0)) != int(user.get("token_version") or 0):
        raise HTTPException(status_code=401, detail="Session no longer valid")
    user["_jti"], user["_exp"] = payload["jti"], payload["exp"]
    return user


_DEV_ADMIN = {"id": "USR-DEV", "name": "Dev Admin", "email": cfg.ADMIN_EMAIL, "role": rbac.ADMIN,
              "org_id": cfg.DEFAULT_ORG_ID, "must_change_password": False}


def require_user(request: Request,
                 creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)) -> Dict[str, Any]:
    """Authenticate (or, with REQUIRE_AUTH=false in development, act as the dev admin)."""
    if not cfg.REQUIRE_AUTH:
        user = dict(_DEV_ADMIN)
    else:
        user = get_current_user(request, creds)
    request.state.user = user
    return user


async def bind_tenant(user: Dict[str, Any] = Depends(require_user)) -> None:
    """Async on purpose: runs in the request task so the contextvar is inherited by the endpoint."""
    tenancy.set_org(user.get("org_id") or cfg.DEFAULT_ORG_ID)


def enforce_permissions(request: Request, user: Dict[str, Any] = Depends(require_user)) -> None:
    if user.get("must_change_password"):
        # Temporary / default credentials: the account can do NOTHING but change its password (the /auth routes, which
        # are not behind this dependency, stay reachable). Previously the flag was only a hint to the web client.
        raise HTTPException(status_code=403, detail="Password change required before using the API")
    needed = rbac.required_role(request.method, request.url.path)
    if not rbac.has_role(user.get("role", ""), needed):
        raise HTTPException(status_code=403, detail=f"Requires role {needed} or higher")


def require_role(minimum: str):
    """Explicit per-route guard (for routes outside the matrix, e.g. auth admin helpers)."""
    def dep(user: Dict[str, Any] = Depends(require_user)) -> Dict[str, Any]:
        if not rbac.has_role(user.get("role", ""), minimum):
            raise HTTPException(status_code=403, detail=f"Requires role {minimum} or higher")
        return user
    return dep
