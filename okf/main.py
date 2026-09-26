"""OKF service entrypoint: FastAPI app + CLI demo. Run: uvicorn main:app --reload"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from src.api_okf import router
from src.cve.api import router as cve_router

app = FastAPI(title="OKF — Operational Knowledge Framework", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)
app.include_router(router)
app.include_router(cve_router)

FRONTEND = Path(__file__).parent / "frontend"
if FRONTEND.exists():
    app.mount("/ui", StaticFiles(directory=str(FRONTEND), html=True), name="ui")

@app.get("/")
def root():
    return {"success": True, "service": "OKF", "version": "1.0.0",
            "docs": "/docs", "endpoints": ["/api/v1/okf/properties", "/api/v1/okf/controls",
            "/api/v1/okf/crosswalk/{id}", "/api/v1/okf/audit", "/api/v1/okf/training/suggest",
            "/api/v1/okf/cve/audit", "/api/v1/okf/cve/sync", "/api/v1/okf/cve/blast-radius"],
            "ui": "/ui (test console)"}
