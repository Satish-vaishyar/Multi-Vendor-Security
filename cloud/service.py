"""Scanner service (runs in the sandboxed container, see Dockerfile and ../docker-compose.cloud.yml).

Endpoints: GET /healthz, POST /scan (raw upload body, X-Filename header). The service holds no credentials and never
initiates outbound connections; /scan refuses to run unless CLOUD_MODULE_ENABLED is on.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse

from cloud import __version__, export, flags, intake, pipeline

app = FastAPI(title="Orbit cloud scanner", version=__version__, docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "version": __version__, "module_enabled": flags.is_enabled()}


@app.post("/scan")
async def scan(request: Request, x_filename: str = Header(default="upload"), x_allow_state: str = Header(default="false")) -> dict:
    if not flags.is_enabled():
        raise HTTPException(503, "cloud module is disabled")
    limit = intake.Limits().max_compressed
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise HTTPException(413, "upload too large")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise HTTPException(413, "upload too large")
    with tempfile.TemporaryDirectory(prefix="scan-") as tmp:
        return pipeline.run_scan(bytes(body), x_filename, Path(tmp), allow_state=x_allow_state.lower() == "true")


_EXPORTERS = {"json": export.to_json, "csv": export.to_csv, "sarif": export.to_sarif}
MAX_EXPORT_BODY = 64 * 1024 * 1024


@app.post("/export/{fmt}")
async def export_report(fmt: str, request: Request) -> PlainTextResponse:
    """Render a stored scan report as JSON / CSV / SARIF. Pure transformation; every string is re-redacted by cloud.export."""
    if not flags.is_enabled():
        raise HTTPException(503, "cloud module is disabled")
    if fmt not in _EXPORTERS:
        raise HTTPException(404, "unknown export format")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_EXPORT_BODY:
            raise HTTPException(413, "report too large")
    try:
        report = json.loads(bytes(body))
    except ValueError:
        raise HTTPException(400, "body must be a JSON report")
    if not isinstance(report, dict):
        raise HTTPException(400, "body must be a JSON report")
    return PlainTextResponse(_EXPORTERS[fmt](report))
