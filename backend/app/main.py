"""SIH-26155 unified backend — FastAPI app (api.md §1, arch.md §51 modular monolith).

Frontend (frontend/index.html) talks ONLY to /api/v1/* over HTTP.
Nothing in the frontend imports backend code directly.
"""
from __future__ import annotations
import logging
import time
import uuid
from pathlib import Path
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.v1 import auth, assets, configurations, audits, findings, training, remediation, reports, misc
from app.api.v1.engines_api import compliance_router, vuln_router, pqc_router, analytics_router
from app.core import config as cfg
from app.core import security as sec

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("sih26155")

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Pre-load the OKF/ML layers once at boot so no user request pays the
    ~40 s cold-start (MiniLM weights + sklearn artifacts stay hot in-process)."""
    t0 = time.time()
    try:
        from app.services import integration as integ
        integ._ensure_bridge()
        import src.embed as _emb
        if getattr(_emb, "_HAS_MINI", False):
            _emb.encode(["warmup"])
        log.info("ML warmup complete (%sms, embeddings=%s)",
                 round((time.time() - t0) * 1000, 1),
                 getattr(_emb, "_MODEL_SOURCE", "tfidf"))
    except Exception as e:
        log.warning("ML warmup skipped: %s", e)
    yield


app = FastAPI(title="SIH-26155 Network Security Compliance Auditor", version="1.0.0",
              docs_url="/docs", redoc_url="/redoc", lifespan=lifespan)

# CORS: wildcard is never combined with credentials (browsers reject it).
_wildcard = "*" in cfg.CORS_ORIGINS
app.add_middleware(CORSMiddleware, allow_origins=["*"] if _wildcard else cfg.CORS_ORIGINS,
                   allow_methods=["*"], allow_headers=["*"], allow_credentials=not _wildcard)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=cfg.TRUSTED_HOSTS)


@app.middleware("http")
async def request_id_logging(request: Request, call_next):  # pragma: no cover - infra
    rid = request.headers.get("X-Request-ID", uuid.uuid4().hex[:12])
    t0 = time.time()
    try:
        resp = await call_next(request)
    except Exception:
        log.exception("req=%s %s %s failed", rid, request.method, request.url.path)
        return JSONResponse({"success": False, "error": {"code": "INTERNAL", "message": "Internal error"}},
                            status_code=500, headers={"X-Request-ID": rid})
    dt = round((time.time() - t0) * 1000, 1)
    log.info("req=%s %s %s -> %s (%sms)", rid, request.method, request.url.path,
             resp.status_code, dt)
    resp.headers["X-Request-ID"] = rid
    return resp


@app.exception_handler(StarletteHTTPException)
async def http_envelope(request: Request, exc: StarletteHTTPException):  # pragma: no cover - infra
    detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
    return JSONResponse({"success": False, "error": {"code": f"HTTP_{exc.status_code}",
                                                    "message": detail}},
                        status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def validation_envelope(request: Request, exc: RequestValidationError):
    return JSONResponse({"success": False, "error": {"code": "VALIDATION_ERROR",
                                                    "message": "Invalid request",
                                                    "details": exc.errors()}},
                        status_code=422)


authed = [Depends(sec.require_user)]
for r in (assets.router, configurations.router, audits.router,
          compliance_router, vuln_router, pqc_router, analytics_router,
          findings.router, training.router, remediation.router, reports.router,
          misc.dashboard_router, misc.okf_router, misc.detect_router):
    app.include_router(r, dependencies=authed)
app.include_router(auth.router)

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


@app.get("/readyz", tags=["meta"])
def readyz():
    """Readiness: DB reachability never raises — reports up/down + 200."""
    db: dict = {"configured": False, "status": "skipped"}
    if cfg.DATABASE_URL:
        db["configured"] = True
        try:
            from app.core.db import ping
            info = ping()
            db.update({"status": "up", "public_tables": info.get("public_tables")})
        except Exception as e:
            db.update({"status": "down", "error": str(e)[:200]})
    return {"success": True, "status": "ready", "env": cfg.ENV, "db": db}


if FRONTEND_DIR.exists():  # pragma: no cover - deploy-time static mount
    @app.get("/ui", tags=["meta"], include_in_schema=False)
    def ui():
        return FileResponse(str(FRONTEND_DIR / "index.html"))
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
