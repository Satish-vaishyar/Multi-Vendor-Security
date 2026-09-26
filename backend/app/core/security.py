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


def _seed_admin() -> None:
    if not db.find("users", email=cfg.ADMIN_EMAIL):
        db.save("users", {
            "id": "USR-001", "name": "Admin", "email": cfg.ADMIN_EMAIL,
            "password_hash": _hash(cfg.ADMIN_PASSWORD), "role": "ADMIN",
        })

_seed_admin()


def authenticate(email: str, password: str) -> Optional[Dict]:
    _seed_admin()
    for u in db.find("users"):
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
    user = db.get("users", payload.get("sub", ""))
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
        _seed_admin()
        user = db.get("users", "USR-001")
        assert user is not None
        return user
    return get_current_user(creds)
