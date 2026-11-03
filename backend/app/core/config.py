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
if ENV not in ("development", "production"):
    # fail closed: a typo such as ENV=prod must never silently switch every production guard off
    raise RuntimeError(f"ENV must be 'development' or 'production' (got {ENV!r})")
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-dev-secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
# Short-lived access tokens; logout / password change revoke them server-side.
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")
DEFAULT_ORG_ID = "ORG-DEFAULT"

# Comma-separated list, e.g. "https://app.example.com,https://admin.example.com".
# "*" is allowed only in development (and never combined with credentials).
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()]
TRUSTED_HOSTS = [h.strip() for h in os.getenv("TRUSTED_HOSTS", "*").split(",") if h.strip()]

# SECURE BY DEFAULT: every /api/v1 route except /auth/login requires a valid
# JWT. Turning it off is a development-only convenience and the app refuses to
# start in production with it off (see validate_production()).
REQUIRE_AUTH = os.getenv("REQUIRE_AUTH", "true").lower() in ("1", "true", "yes")
MAX_BULK_FILES = int(os.getenv("MAX_BULK_FILES", "20"))
# Request-size limits enforced by the app while the body streams in (nginx has its own, see frontend/nginx.conf).
MAX_JSON_BODY_BYTES = int(os.getenv("MAX_JSON_BODY_BYTES", str(8 * 1024 * 1024)))          # every non-multipart request
MAX_UPLOAD_BODY_BYTES = int(os.getenv("MAX_UPLOAD_BODY_BYTES", str(110 * 1024 * 1024)))    # multipart/form-data (config uploads)
# Per-organisation (and per-user) token bucket for expensive POST endpoints (audits, reports, uploads, AI, CVE sync).
# Per process: with N API workers the effective ceiling is N x this value. 0 disables the limiter.
RATE_LIMIT_EXPENSIVE_PER_MIN = int(os.getenv("RATE_LIMIT_EXPENSIVE_PER_MIN", "120"))
RATE_LIMIT_EXPENSIVE_BURST = int(os.getenv("RATE_LIMIT_EXPENSIVE_BURST", "30"))
# Count rate limits in Postgres so all API processes / replicas share one budget (falls back to per-process if the DB errors).
RATE_LIMIT_SHARED = os.getenv("RATE_LIMIT_SHARED", "true").strip().lower() in ("1", "true", "yes", "on")

# Background jobs (Postgres queue; see app/core/jobs.py)
MAX_BATCH_FILES = int(os.getenv("MAX_BATCH_FILES", "500"))           # files per async bulk-audit request
MAX_QUEUED_JOBS_PER_ORG = int(os.getenv("MAX_QUEUED_JOBS_PER_ORG", "5000"))
JOB_MAX_ATTEMPTS = int(os.getenv("JOB_MAX_ATTEMPTS", "3"))
JOB_STALE_SECONDS = int(os.getenv("JOB_STALE_SECONDS", "900"))       # a RUNNING job with no heartbeat this long is re-queued
JOB_RETENTION_DAYS = int(os.getenv("JOB_RETENTION_DAYS", "30"))
SNAPSHOT_RETENTION_DAYS = int(os.getenv("SNAPSHOT_RETENTION_DAYS", "365"))
# Data retention (app/services/retention.py). Purges are cross-tenant and age-based; 0 disables a rule.
RETENTION_ENABLED = os.getenv("RETENTION_ENABLED", "true").lower() in ("1", "true", "yes")
AUDIT_LOG_RETENTION_DAYS = int(os.getenv("AUDIT_LOG_RETENTION_DAYS", "400"))
# White-label report branding (empty = built-in branding). Used on the PDF cover/header and the page footer.
REPORT_BRAND_NAME = os.getenv("REPORT_BRAND_NAME", "").strip()[:80]
REPORT_BRAND_FOOTER = os.getenv("REPORT_BRAND_FOOTER", "").strip()[:140]
# Ticketing webhook defaults (format=jira / servicenow)
WEBHOOK_JIRA_PROJECT = os.getenv("WEBHOOK_JIRA_PROJECT", "SEC").strip()[:40]
WEBHOOK_JIRA_ISSUE_TYPE = os.getenv("WEBHOOK_JIRA_ISSUE_TYPE", "Task").strip()[:40]
REPORT_PDF_RETENTION_DAYS = int(os.getenv("REPORT_PDF_RETENTION_DAYS", "365"))      # PDF bytes dropped, report metadata kept
WEBHOOK_DELIVERY_RETENTION_DAYS = int(os.getenv("WEBHOOK_DELIVERY_RETENTION_DAYS", "30"))
CONFIG_RETENTION_DAYS = int(os.getenv("CONFIG_RETENTION_DAYS", "0"))                # raw text of SUPERSEDED configs; 0 = keep (default)
# Observability
METRICS_TOKEN = os.getenv("METRICS_TOKEN", "")          # required in production: Authorization: Bearer <token> for GET /metrics
LOG_FORMAT = os.getenv("LOG_FORMAT", "text").lower()    # text | json
BUILD_VERSION = os.getenv("BUILD_VERSION", "1.0.0")
CVE_AUTO_SYNC_HOURS = float(os.getenv("CVE_AUTO_SYNC_HOURS", "0"))  # >0: each worker refreshes its CVE KB (NVD delta + CISA KEV) this often; 0 = off
CVE_AUTO_SYNC_DAYS = int(os.getenv("CVE_AUTO_SYNC_DAYS", "7"))      # NVD lastModified window per refresh
EXCEPTION_MAX_DAYS = int(os.getenv("EXCEPTION_MAX_DAYS", "180"))          # longest allowed risk acceptance
MFA_REQUIRED_ROLES = {r.strip().upper() for r in os.getenv("MFA_REQUIRED_ROLES", "ADMIN").split(",") if r.strip()}  # roles told to enrol MFA
# Enforce (not just prompt) MFA enrolment for MFA_REQUIRED_ROLES: until enrolled such an account can only reach /auth/*.
# On by default in production; SSO users are exempt (the identity provider owns their second factor).
MFA_ENFORCE = os.getenv("MFA_ENFORCE", "true" if ENV == "production" else "false").lower() in ("1", "true", "yes")
SESSION_COOKIE = os.getenv("SESSION_COOKIE", "qirova_session")      # httpOnly session token (web client opts in via X-Auth-Mode: cookie)
CSRF_COOKIE = os.getenv("CSRF_COOKIE", "qirova_csrf")                # readable double-submit CSRF token
SCHEDULE_MIN_MINUTES = int(os.getenv("SCHEDULE_MIN_MINUTES", "15"))        # shortest allowed recurring-audit interval
MAX_SCHEDULES_PER_ORG = int(os.getenv("MAX_SCHEDULES_PER_ORG", "1000"))
# Outbound webhooks (see app/core/urlcheck.py for the SSRF policy)
WEBHOOK_ALLOW_PRIVATE = os.getenv("WEBHOOK_ALLOW_PRIVATE", "false").lower() in ("1", "true", "yes")   # allow RFC1918 destinations
WEBHOOK_ALLOW_HTTP = os.getenv("WEBHOOK_ALLOW_HTTP", "false").lower() in ("1", "true", "yes")         # plain http in production
WEBHOOK_TIMEOUT_S = float(os.getenv("WEBHOOK_TIMEOUT_S", "10"))
WEBHOOK_MAX_PER_ORG = int(os.getenv("WEBHOOK_MAX_PER_ORG", "50"))
WEBHOOK_DISABLE_AFTER = int(os.getenv("WEBHOOK_DISABLE_AFTER", "20"))   # consecutive failed deliveries before auto-disable
WORKER_POLL_SECONDS = float(os.getenv("WORKER_POLL_SECONDS", "2"))
# Run a worker thread inside the API process. Convenient for development / single-container installs;
# production should run dedicated workers (python -m app.worker) so API latency is unaffected by audits.
EMBEDDED_WORKER = os.getenv("EMBEDDED_WORKER", "false" if os.getenv("ENV", "development").lower() == "production" else "true").lower() in ("1", "true", "yes")
DATABASE_URL = os.getenv("DATABASE_URL", "")

# Login protection
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))          # per account
LOGIN_LOCKOUT_MINUTES = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "15"))
LOGIN_IP_MAX_PER_MINUTE = int(os.getenv("LOGIN_IP_MAX_PER_MINUTE", "20"))  # per client IP
PASSWORD_MIN_LENGTH = int(os.getenv("PASSWORD_MIN_LENGTH", "12"))
PASSWORD_HASH_ITERATIONS = int(os.getenv("PASSWORD_HASH_ITERATIONS", "600000"))  # PBKDF2-HMAC-SHA256 (OWASP 2023)

# Encryption at rest for sensitive fields (device configs, raw unknown lines).
# Comma-separated Fernet keys, newest first (rotation = prepend a new key).
DATA_ENCRYPTION_KEYS = [k.strip() for k in os.getenv("DATA_ENCRYPTION_KEYS", "").split(",") if k.strip()]

# Key management: "env" (keys above), or envelope encryption through Vault Transit / AWS KMS (docs/SECURITY.md).
KEY_PROVIDER = os.getenv("KEY_PROVIDER", "env").strip().lower()
DATA_ENCRYPTION_KEYS_WRAPPED = [k.strip() for k in os.getenv("DATA_ENCRYPTION_KEYS_WRAPPED", "").split(",") if k.strip()]
VAULT_ADDR = os.getenv("VAULT_ADDR", "")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "")
VAULT_TRANSIT_KEY = os.getenv("VAULT_TRANSIT_KEY", "")
VAULT_NAMESPACE = os.getenv("VAULT_NAMESPACE", "")
AWS_REGION = os.getenv("AWS_REGION", "")
KMS_KEY_ID = os.getenv("KMS_KEY_ID", "")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
AWS_SESSION_TOKEN = os.getenv("AWS_SESSION_TOKEN", "")

# Live collection over SSH (read-only; see app/core/collector.py)
COLLECT_ALLOW_PRIVATE = os.getenv("COLLECT_ALLOW_PRIVATE", "true").lower() in ("1", "true", "yes")   # devices are usually private
COLLECT_ALLOWED_CIDRS = [c.strip() for c in os.getenv("COLLECT_ALLOWED_CIDRS", "").split(",") if c.strip()]  # recommended in production
COLLECT_ALLOW_LOOPBACK = os.getenv("COLLECT_ALLOW_LOOPBACK", "false").lower() in ("1", "true", "yes")  # development/tests only
COLLECT_TIMEOUT_S = float(os.getenv("COLLECT_TIMEOUT_S", "30"))
COLLECT_MAX_BYTES = int(os.getenv("COLLECT_MAX_BYTES", str(8 * 1024 * 1024)))

# Single sign-on (OpenID Connect). Empty OIDC_ISSUER = SSO off. See docs/SECURITY.md "Single sign-on".
OIDC_ISSUER = os.getenv("OIDC_ISSUER", "").strip()
OIDC_CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "").strip()
OIDC_CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "")
OIDC_REDIRECT_URI = os.getenv("OIDC_REDIRECT_URI", "").strip()     # https://<api-host>/api/v1/auth/sso/callback
OIDC_SCOPES = os.getenv("OIDC_SCOPES", "openid email profile")
OIDC_PROVIDER_NAME = os.getenv("OIDC_PROVIDER_NAME", "single sign-on")
OIDC_GROUPS_CLAIM = os.getenv("OIDC_GROUPS_CLAIM", "groups")
OIDC_ROLE_MAP = os.getenv("OIDC_ROLE_MAP", "{}")                   # JSON: {"idp-group-name": "ADMIN", ...}
OIDC_DEFAULT_ROLE = os.getenv("OIDC_DEFAULT_ROLE", "")              # empty = users with no mapped group are refused
OIDC_ORG_ID = os.getenv("OIDC_ORG_ID", "")                          # tenant new SSO users are created in (default org)
OIDC_ALLOWED_DOMAINS = [d.strip() for d in os.getenv("OIDC_ALLOWED_DOMAINS", "").split(",") if d.strip()]
OIDC_AUTO_PROVISION = os.getenv("OIDC_AUTO_PROVISION", "true").lower() in ("1", "true", "yes")
OIDC_LINK_EXISTING_USERS = os.getenv("OIDC_LINK_EXISTING_USERS", "false").lower() in ("1", "true", "yes")
OIDC_FRONTEND_URL = os.getenv("OIDC_FRONTEND_URL", "http://localhost:5173")   # where the browser lands after login
SSO_ONLY = os.getenv("SSO_ONLY", "false").lower() in ("1", "true", "yes")     # refuse password login for non-admins

# Customer configs never leave the network unless the operator opts in.
ALLOW_EXTERNAL_LLM = os.getenv("ALLOW_EXTERNAL_LLM", "false").lower() in ("1", "true", "yes")

# Interactive docs / legacy UI: on in development, off in production unless forced.
ENABLE_DOCS = os.getenv("ENABLE_DOCS", "false" if ENV == "production" else "true").lower() in ("1", "true", "yes")

_DEV_SECRETS = {"change-me-dev-secret", "change-me-to-a-long-random-string", ""}
_WEAK_ADMIN_PASSWORDS = {"admin123", "admin", "password", "changeme", "change-me", ""}


def validate_production() -> list[str]:
    """Return a list of configuration problems that make a production start unsafe."""
    problems: list[str] = []
    if ENV != "production":
        return problems
    if JWT_SECRET in _DEV_SECRETS or len(JWT_SECRET) < 32:
        problems.append("JWT_SECRET must be a random value of at least 32 characters")
    if not REQUIRE_AUTH:
        problems.append("REQUIRE_AUTH must be true")
    if ADMIN_PASSWORD.lower() in _WEAK_ADMIN_PASSWORDS or len(ADMIN_PASSWORD) < PASSWORD_MIN_LENGTH:
        problems.append(f"ADMIN_PASSWORD is weak/default (min {PASSWORD_MIN_LENGTH} chars, not a known default)")
    if JWT_ALGORITHM not in ("HS256", "HS384", "HS512"):
        problems.append("JWT_ALGORITHM must be one of HS256, HS384, HS512")
    if JWT_EXPIRE_MINUTES > 1440 or JWT_EXPIRE_MINUTES < 1:
        problems.append("JWT_EXPIRE_MINUTES must be between 1 and 1440")
    if PASSWORD_HASH_ITERATIONS < 210_000:
        problems.append("PASSWORD_HASH_ITERATIONS must be at least 210000 in production")
    if "*" in CORS_ORIGINS:
        problems.append("CORS_ORIGINS must list explicit origins (no '*')")
    if "*" in TRUSTED_HOSTS:
        problems.append("TRUSTED_HOSTS must list explicit hosts (no '*')")
    from app.core import keyprovider
    problems.extend(keyprovider.problems())
    if not DATABASE_URL:
        problems.append("DATABASE_URL must be set")
    return problems


def production_warnings() -> list[str]:
    """Non-fatal production findings (the service starts, but a feature is degraded)."""
    warns: list[str] = []
    if ENV == "production" and ADMIN_EMAIL.lower() == "admin@example.com":
        warns.append("ADMIN_EMAIL is still the example default; use a real, monitored address for the bootstrap admin")
    if ENV == "production" and WEBHOOK_ALLOW_PRIVATE:
        warns.append("WEBHOOK_ALLOW_PRIVATE=true: tenant admins can aim webhooks at your internal (RFC1918) network")
    if ENV == "production" and RATE_LIMIT_EXPENSIVE_PER_MIN <= 0:
        warns.append("RATE_LIMIT_EXPENSIVE_PER_MIN=0: expensive endpoints (audit/report/upload/AI) are not rate limited")
    if ENV == "production" and os.getenv("RLS_ENABLED", "false").lower() not in ("1", "true", "yes"):
        warns.append("RLS_ENABLED is off: tenant isolation is enforced by the application only; enable Postgres row-level "
                     "security (python -m app.cli rls-enable) as defence in depth")
    if ENV == "production" and COLLECT_ALLOW_PRIVATE and not COLLECT_ALLOWED_CIDRS:
        warns.append("COLLECT_ALLOWED_CIDRS is empty: tenant admins can aim SSH collection at any private address; "
                     "list the device ranges")
    if ENV == "production" and len(METRICS_TOKEN) < 16:
        warns.append("METRICS_TOKEN is not set (>= 16 chars): GET /metrics is refused (503) until it is configured")
    return warns


if ENV == "production":
    _problems = validate_production()
    if _problems:  # pragma: no cover - prod guard (covered by test via validate_production)
        raise RuntimeError("Unsafe production configuration:\n - " + "\n - ".join(_problems))


def ok(data: Any = None, message: str = "ok", request_id: Optional[str] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {"success": True, "data": data, "message": message}
    if request_id:
        out["request_id"] = request_id
    return out


def err(code: str, message: str, details: Any = None, status: int = 400) -> Dict[str, Any]:
    return {"success": False, "error": {"code": code, "message": message, "details": details or {}}}
