"""JWT auth + RBAC (arch.md §47). Demo user seeded from env."""
from __future__ import annotations
import time
from typing import Dict, Optional
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import hashlib
import os as _os
import hmac as _hmac

from app.core import config as cfg
from app.core import persist as db

_bearer = HTTPBearer(auto_error=False)


def _hash(password: str) -> str:
    salt = _os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return f"pbkdf2$200000${salt.hex()}${dk.hex()}"


def _verify(password: str, stored: str) -> bool:
    try:
        _, iters, salt_h, dk_h = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_h), int(iters))
        return _hmac.compare_digest(dk.hex(), dk_h)
    except Exception:
        return False


def _seed_admin() -> bool:
    """Ensure the seeded admin exists. Never raises — returns False when the
    DB is unreachable so importing this module (and booting uvicorn) can never
    crash on a DB outage; /readyz still reports the DB as down."""
    try:
        if not db.find("users", email=cfg.ADMIN_EMAIL):
            db.save("users", {
                "id": "USR-001", "name": "Admin", "email": cfg.ADMIN_EMAIL,
                "password_hash": _hash(cfg.ADMIN_PASSWORD), "role": "ADMIN",
            })
        return True
    except Exception as e:
        import logging as _logging
        _logging.getLogger("sih26155").warning("admin seed skipped (db unreachable): %s", e)
        return False


def authenticate(email: str, password: str) -> Optional[Dict]:
    if not _seed_admin():
        return None
    try:
        users = db.find("users")
    except Exception:
        return None
    for u in users:
        if u["email"].lower() == email.lower() and _verify(password, u["password_hash"]):
            return u
    return None


def make_token(user: Dict) -> Dict:
    exp = int(time.time()) + cfg.JWT_EXPIRE_MINUTES * 60
    payload = {"sub": user["id"], "email": user["email"], "role": user["role"], "exp": exp}
    token = jwt.encode(payload, cfg.JWT_SECRET, algorithm=cfg.JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "expires_in": cfg.JWT_EXPIRE_MINUTES * 60,
            "user": {"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"]}}


def get_current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)) -> Dict:
    if not creds:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    try:
        payload = jwt.decode(creds.credentials, cfg.JWT_SECRET, algorithms=[cfg.JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    try:
        user = db.get("users", payload.get("sub", ""))
    except Exception:
        raise HTTPException(status_code=503, detail="Database unavailable")
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)) -> Dict:
    """Env-gated auth dependency for all /api/v1 routers except login.

    REQUIRE_AUTH=false (dev/test default): returns the seeded admin without
    requiring a token, so existing flows and tests work unchanged.
    REQUIRE_AUTH=true (production): enforces a valid JWT.
    """
    if not cfg.REQUIRE_AUTH:
        return _admin_user()
    return get_current_user(creds)


# In-process cache for the hot auth path: require_user runs before EVERY
# /api/v1 request, so it must not hit Postgres each time (2 extra roundtrips).
_ADMIN_CACHE: Optional[Dict] = None


def _admin_user() -> Dict:
    """Seeded admin, loaded once per process (login/tests still use the DB).

    When the DB is unreachable (local dev without network), falls back to an
    ephemeral in-memory admin so REQUIRE_AUTH=false routes keep working and
    the process never crashes at import/request time.
    """
    global _ADMIN_CACHE
    if _ADMIN_CACHE is None:
        if _seed_admin():
            try:
                user = db.get("users", "USR-001")
            except Exception:
                user = None
            assert user is not None
            _ADMIN_CACHE = user
        else:
            return {"id": "USR-001", "name": "Admin",
                    "email": cfg.ADMIN_EMAIL, "role": "ADMIN"}
    return _ADMIN_CACHE
