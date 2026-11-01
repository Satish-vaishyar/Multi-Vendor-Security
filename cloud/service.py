"""Scanner service (runs in the sandboxed container, see Dockerfile and ../docker-compose.cloud.yml).

S03 exposes liveness only; the scan endpoint arrives in S04. The service holds no credentials and never initiates
outbound connections.
"""
from __future__ import annotations

from fastapi import FastAPI

from cloud import __version__, flags

app = FastAPI(title="Orbit cloud scanner", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "version": __version__, "module_enabled": flags.is_enabled()}
