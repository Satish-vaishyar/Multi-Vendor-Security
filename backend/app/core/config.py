"""Config via env/.env + common API response envelope (api.md §3)."""
from __future__ import annotations
import os
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - dotenv is a declared dependency
    load_dotenv = None


def _load_env() -> None:
    if load_dotenv is None:  # pragma: no cover - defensive
        return
    try:
        load_dotenv(Path(__file__).parent.parent.parent / ".env")
    except Exception:
        pass


_load_env()

BACKEND_ROOT = Path(__file__).parent.parent.parent
OKF_DIR = Path(os.getenv("OKF_DIR", str(BACKEND_ROOT.parent / "okf")))
MODELS_DIR = Path(os.getenv("MODELS_DIR", str(BACKEND_ROOT.parent / "models")))

ENV = os.getenv("ENV", "development").lower()  # development | production
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-dev-secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "720"))
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# Comma-separated list, e.g. "https://app.example.com,https://admin.example.com".
# "*" is allowed only in development (and never combined with credentials).
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()]
TRUSTED_HOSTS = [h.strip() for h in os.getenv("TRUSTED_HOSTS", "*").split(",") if h.strip()]

# When true, every /api/v1 route except /auth/login, / and /health requires a
# valid JWT. Default false so existing tests + local dev work unchanged;
# set REQUIRE_AUTH=true in production.
REQUIRE_AUTH = os.getenv("REQUIRE_AUTH", "false").lower() in ("1", "true", "yes")
MAX_BULK_FILES = int(os.getenv("MAX_BULK_FILES", "20"))
DATABASE_URL = os.getenv("DATABASE_URL", "")

_DEV_SECRETS = {"change-me-dev-secret", "change-me-to-a-long-random-string", ""}
if ENV == "production" and JWT_SECRET in _DEV_SECRETS:
    raise RuntimeError("JWT_SECRET must be set to a strong random value in production")  # pragma: no cover - prod guard


def ok(data: Any = None, message: str = "ok", request_id: Optional[str] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {"success": True, "data": data, "message": message}
    if request_id:
        out["request_id"] = request_id
    return out


def err(code: str, message: str, details: Any = None, status: int = 400) -> Dict[str, Any]:
    return {"success": False, "error": {"code": code, "message": message, "details": details or {}}}
