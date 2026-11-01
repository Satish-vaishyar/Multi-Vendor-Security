"""SIH-26155 unified backend — FastAPI app (api.md §1, arch.md §51 modular monolith).

Frontend (frontend/index.html) talks ONLY to /api/v1/* over HTTP.
Nothing in the frontend imports backend code directly.
"""
from __future__ import annotations
import logging
import os
import re
import time
import uuid
from pathlib import Path
import psycopg
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.v1 import admin, auth, collection as collection_api, fix_verification as fix_verification_api, sso as sso_api, exceptions as exceptions_api, history as history_api, integrations as integrations_api, jobs as jobs_api, assets, configurations, audits, findings, training, remediation, reports, misc
from app.api.v1.engines_api import compliance_router, vuln_router, pqc_router, analytics_router
from app.core import config as cfg
from app.core import security as sec
from app.core import auditlog
from app.core import limits, logsetup, metrics

logsetup.configure()   # text or JSON (LOG_FORMAT) with secret redaction
log = logging.getLogger("sih26155")

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Pre-load the OKF/ML layers once at boot so no user request pays the
    ~40 s cold-start (MiniLM weights + sklearn artifacts stay hot in-process)."""
    t0 = time.time()
    for w in cfg.production_warnings():
        log.warning("config warning: %s", w)
    sec.ensure_bootstrap_admin()
    try:
        from app.core.db import ping as _ping
        if cfg.DATABASE_URL and not _ping().get("schema_current", True):
            log.error("DATABASE SCHEMA OUTDATED - run: python -m app.cli migrate (requests will fail until then)")
    except Exception as e:  # pragma: no cover - startup diagnostics only
        log.warning("schema check skipped: %s", e)
    try:
        from app.services import integration as integ
        integ._ensure_bridge()
        for _warm in (integ.okf_layer, integ.learning_engine, integ.cve_layer, lambda: integ.m1_predict("hostname warmup")):
            try:
                _warm()
            except Exception as _e:  # pragma: no cover - warmup is best effort
                log.warning("warmup step skipped: %s", _e)
        import src.embed as _emb
        if getattr(_emb, "_HAS_MINI", False):
            _emb.encode(["warmup"])
        log.info("ML warmup complete (%sms, embeddings=%s)",
                 round((time.time() - t0) * 1000, 1),
                 getattr(_emb, "_MODEL_SOURCE", "tfidf"))
    except Exception as e:
        log.warning("ML warmup skipped: %s", e)
    stop_worker = None
    if cfg.EMBEDDED_WORKER:
        from app import worker as _worker
        stop_worker = _worker.start_embedded()
        log.info("embedded background worker started")
    yield
    if stop_worker is not None:
        stop_worker.set()


app = FastAPI(title="SIH-26155 Network Security Compliance Auditor", version="1.0.0",
              docs_url="/docs" if cfg.ENABLE_DOCS else None,
              redoc_url="/redoc" if cfg.ENABLE_DOCS else None,
              openapi_url="/openapi.json" if cfg.ENABLE_DOCS else None,
              lifespan=lifespan)

# Innermost on purpose: its 413 passes back through the CORS / request-id / security-header middleware below.
app.add_middleware(limits.BodyLimitMiddleware)

# CORS: wildcard is never combined with credentials (browsers reject it).
_wildcard = "*" in cfg.CORS_ORIGINS
app.add_middleware(CORSMiddleware, allow_origins=["*"] if _wildcard else cfg.CORS_ORIGINS,
                   allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
                   allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-CSRF-Token", "X-Auth-Mode"],
                   expose_headers=["X-Request-ID"], allow_credentials=not _wildcard)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=cfg.TRUSTED_HOSTS)


_RID_OK = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_API_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


@app.middleware("http")
async def request_id_logging(request: Request, call_next):  # pragma: no cover - infra
    rid = request.headers.get("X-Request-ID", "")
    if not _RID_OK.match(rid):  # never echo attacker-controlled text into logs/headers
        rid = uuid.uuid4().hex[:12]
    request.state.user = None
    logsetup.request_id_var.set(rid)
    t0 = time.time()
    metrics.in_flight_inc()
    try:
        resp = await call_next(request)
    except Exception:
        log.exception("req=%s %s %s failed", rid, request.method, request.url.path)
        resp = JSONResponse({"success": False, "error": {"code": "INTERNAL", "message": "Internal error"}},
                            status_code=500)
    finally:
        metrics.in_flight_dec()
    dt = round((time.time() - t0) * 1000, 1)
    metrics.observe(request.method, metrics.route_template(request), resp.status_code, dt / 1000.0)
    log.info("req=%s %s %s -> %s (%sms)", rid, request.method, request.url.path,
             resp.status_code, dt,
             extra={"request_id": rid, "org_id": (getattr(request.state, "user", None) or {}).get("org_id")})
    resp.headers["X-Request-ID"] = rid
    for k, v in _API_HEADERS.items():
        resp.headers.setdefault(k, v)
    if request.url.path.startswith("/api/"):
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    if cfg.ENV == "production":
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    path = request.url.path
    if (path.startswith("/api/") and auditlog.should_log(request.method, path)
            and path not in ("/api/v1/auth/login", "/api/v1/auth/logout", "/api/v1/auth/change-password")):
        u = getattr(request.state, "user", None)  # auth endpoints write their own richer events
        auditlog.record(f"{request.method} {path.split('/')[3] if path.count('/') >= 3 else path}", actor=u,
                        method=request.method, path=path, status=resp.status_code,
                        ip=request.client.host if request.client else "", request_id=rid)
    return resp


@app.exception_handler(StarletteHTTPException)
async def http_envelope(request: Request, exc: StarletteHTTPException):  # pragma: no cover - infra
    detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
    return JSONResponse({"success": False, "error": {"code": f"HTTP_{exc.status_code}",
                                                    "message": detail}},
                        status_code=exc.status_code, headers=getattr(exc, "headers", None))


@app.exception_handler(psycopg.errors.DataError)
async def bad_data_envelope(request: Request, exc: psycopg.errors.DataError):
    """NUL bytes / un-storable characters inside a JSON body: the client's fault, not a server error."""
    return JSONResponse({"success": False, "error": {"code": "BAD_DATA", "message": "Request contains characters that cannot be stored"}},
                        status_code=400)


@app.exception_handler(RequestValidationError)
async def validation_envelope(request: Request, exc: RequestValidationError):
    # Never echo the submitted values (they may be passwords / config text) or exception objects back.
    details = [{"loc": list(e.get("loc", ())), "msg": str(e.get("msg", "")), "type": str(e.get("type", ""))}
               for e in exc.errors()]
    return JSONResponse({"success": False, "error": {"code": "VALIDATION_ERROR",
                                                    "message": "Invalid request",
                                                    "details": details}},
                        status_code=422)


authed = [Depends(sec.require_user), Depends(sec.bind_tenant), Depends(sec.enforce_permissions),
          Depends(limits.rate_limit)]
for r in (assets.router, configurations.router, audits.router,
          compliance_router, vuln_router, pqc_router, analytics_router,
          findings.router, training.router, remediation.router, reports.router,
          misc.dashboard_router, misc.okf_router, misc.detect_router, admin.router, jobs_api.router, history_api.router, history_api.sched_router, integrations_api.router, exceptions_api.router, collection_api.router, fix_verification_api.router):
    app.include_router(r, dependencies=authed)
if os.environ.get("CLOUD_MODULE_ENABLED", "").strip().lower() in ("1", "true", "yes", "on"):
    from app.api.v1 import cloud as cloud_api      # optional module (docs/CLOUD_MODULE_RTM.md); off unless explicitly enabled
    app.include_router(cloud_api.router, dependencies=authed)
app.include_router(auth.router)
app.include_router(sso_api.router)

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


@app.get("/", tags=["meta"])
def root():
    return {"success": True, "service": "SIH-26155 auditor backend", "version": "1.0.0",
            "base": "/api/v1", "docs": "/docs", "ui": "/ui",
            "groups": ["auth", "assets", "configurations", "audits", "compliance",
                       "vulnerabilities", "pqc", "analytics", "findings", "training",
                       "remediation", "reports", "dashboard", "okf", "detection"]}


@app.get("/health", tags=["meta"])
def health():
    return {"success": True, "status": "healthy"}


@app.get("/metrics", tags=["meta"], include_in_schema=False)
def prometheus_metrics(request: Request):
    """Prometheus text exposition. Requires `Authorization: Bearer <METRICS_TOKEN>` when METRICS_TOKEN is set;
    in production it is refused (503) unless METRICS_TOKEN is configured."""
    allowed, code, reason = metrics.check_token(request.headers.get("Authorization"))
    if not allowed:
        return JSONResponse({"success": False, "error": {"code": f"HTTP_{code}", "message": reason}}, status_code=code,
                            headers={"WWW-Authenticate": "Bearer"} if code == 401 else None)
    return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4; charset=utf-8")


@app.get("/readyz", tags=["meta"])
def readyz():
    """Readiness: 200 when dependencies are up, 503 when the DB is configured but down."""
    db: dict = {"configured": False, "status": "skipped"}
    if cfg.DATABASE_URL:
        db["configured"] = True
        try:
            from app.core.db import ping
            info = ping()
            db.update({"status": "up", "public_tables": info.get("public_tables")})
            if not info.get("schema_current", True):
                db.update({"status": "down", "error": "database schema is outdated - run: python -m app.cli migrate"})
        except Exception as e:
            # driver errors can carry the DB host / user: only show them outside production
            db.update({"status": "down", "error": "database unreachable" if cfg.ENV == "production" else str(e)[:200]})
    if db["status"] == "down":
        return JSONResponse({"success": False, "status": "not_ready", "env": cfg.ENV, "db": db},
                            status_code=503)
    return {"success": True, "status": "ready", "env": cfg.ENV, "db": db}


if cfg.ENABLE_DOCS and FRONTEND_DIR.exists():  # pragma: no cover - dev-only legacy UI
    @app.get("/ui", tags=["meta"], include_in_schema=False)
    def ui():
        return FileResponse(str(FRONTEND_DIR / "index.html"))
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
