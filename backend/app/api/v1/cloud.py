"""Cloud security assessment API (docs/CLOUD_MODULE_RTM.md, S04/S14). Thin by design: the upload is forwarded to the sandboxed
scanner service over the internal network (the backend never parses or executes uploaded infrastructure code) and the result
is stored in the module's own tables. The router is only mounted when CLOUD_MODULE_ENABLED is on, and every route re-checks it."""
from __future__ import annotations
import json
import os
import re
import uuid
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, File, HTTPException, Query, Response, UploadFile

from app.core import auditlog
from app.core import cloud_store as store
from app.core import config as cfg
from app.core import security as sec

router = APIRouter(prefix="/api/v1/cloud", tags=["cloud"])

MAX_UPLOAD = 50 * 1024 * 1024
_SCAN_ID = re.compile(r"^CSCAN-[0-9a-f]{16}$")
_FORMATS = {"json": "application/json", "csv": "text/csv", "sarif": "application/sarif+json"}
_TRUE = {"1", "true", "yes", "on"}


def enabled() -> bool:
    """Fail-closed, identical to cloud.flags.is_enabled (the backend image does not ship the cloud package)."""
    return os.environ.get("CLOUD_MODULE_ENABLED", "").strip().lower() in _TRUE


def _scanner_url() -> str:
    return os.environ.get("CLOUD_SCANNER_URL", "http://cloud-scanner:8100").rstrip("/")


def _guard() -> None:
    if not enabled():
        raise HTTPException(404, "Not found")


def _check_id(scan_id: str) -> str:
    if not _SCAN_ID.match(scan_id):
        raise HTTPException(404, "scan not found")
    return scan_id


def _scanner_post(path: str, content: bytes, headers: dict, timeout: float) -> httpx.Response:
    try:
        return httpx.post(_scanner_url() + path, content=content, headers=headers, timeout=timeout)
    except httpx.HTTPError:
        raise HTTPException(502, "cloud scanner unavailable")


@router.get("/status")
def status():
    _guard()
    try:
        r = httpx.get(_scanner_url() + "/healthz", timeout=3)
        scanner = r.json() if r.status_code == 200 else {"status": "error"}
    except (httpx.HTTPError, ValueError):
        scanner = {"status": "unreachable"}
    return cfg.ok({"enabled": True, "scanner": scanner})


@router.post("/scans", status_code=201)
async def create_scan(file: UploadFile = File(...), user=Depends(sec.require_user)):
    _guard()
    data = await file.read(MAX_UPLOAD + 1)
    if not data:
        raise HTTPException(400, "empty upload")
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "upload too large")
    name = re.sub(r"[^\w.\- ]", "_", os.path.basename((file.filename or "upload").replace("\\", "/")))[:200] or "upload"
    r = _scanner_post("/scan", data, {"X-Filename": name, "Content-Type": "application/octet-stream"}, 120)
    if r.status_code != 200:
        raise HTTPException(502 if r.status_code >= 500 else 400, "the scanner refused the upload")
    try:
        report = r.json()
    except ValueError:
        raise HTTPException(502, "invalid scanner response")
    scan_id = "CSCAN-" + uuid.uuid4().hex[:16]
    who = str(user.get("email") or user.get("id") or "unknown")
    try:
        store.save_report(scan_id, report, who)
    except PermissionError:
        raise HTTPException(409, "scan id conflict")
    auditlog.record("cloud.scan.created", actor=user, detail={"scan_id": scan_id, "file": name, "status": report.get("status")})
    return cfg.ok({"scan_id": scan_id, "status": report.get("status"), "summary": report.get("summary"),
                   "statement": report.get("statement"), "coverage": report.get("coverage")})


@router.get("/scans")
def list_scans(limit: int = Query(50, ge=1, le=200)):
    _guard()
    return cfg.ok({"items": store.list_scans(limit)})


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    _guard()
    scan = store.get_scan(_check_id(scan_id))
    if not scan:
        raise HTTPException(404, "scan not found")
    return cfg.ok(scan)


@router.get("/scans/{scan_id}/findings")
def findings(scan_id: str, state: Optional[str] = None, severity: Optional[str] = None,
             page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200)):
    _guard()
    if not store.get_scan(_check_id(scan_id)):
        raise HTTPException(404, "scan not found")
    return cfg.ok(store.list_findings(scan_id, state, severity, page, size))


@router.get("/scans/{scan_id}/export")
def export(scan_id: str, format: str = Query("json")):
    _guard()
    if format not in _FORMATS:
        raise HTTPException(400, f"format must be one of {sorted(_FORMATS)}")
    report = store.report_for_export(_check_id(scan_id))
    if report is None:
        raise HTTPException(404, "scan not found")
    r = _scanner_post(f"/export/{format}", json.dumps(report, default=str).encode("utf-8"), {"Content-Type": "application/json"}, 60)
    if r.status_code != 200:
        raise HTTPException(502, "export failed")
    return Response(r.content, media_type=_FORMATS[format],
                    headers={"Content-Disposition": f'attachment; filename="{scan_id}.{format}"', "X-Content-Type-Options": "nosniff"})
