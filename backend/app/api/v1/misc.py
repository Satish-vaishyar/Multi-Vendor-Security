"""Dashboard summary, OKF browser, vendor detection (api.md §29-30, §32)."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from app.core import config as cfg
from app.core import persist as db
from app.parsers import vendor_detector
from app.services.integration import okf_layer

dashboard_router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])
okf_router = APIRouter(prefix="/api/v1/okf", tags=["okf"])
detect_router = APIRouter(prefix="/api/v1/detection", tags=["detection"])


@dashboard_router.get("/summary")
def summary():
    """Fleet-wide aggregates (SQL GROUP BY, org-scoped, short per-org TTL cache).

    Legacy keys (assets/compliance/frameworks/findings/cve/pqc/training) are kept;
    by_severity / by_engine / by_vendor / score_distribution / top_failing_controls /
    trend / totals are additive.
    """
    from app.services import dashboard
    return cfg.ok(dashboard.summary())


@okf_router.get("/properties")
def okf_properties(category: Optional[str] = None):
    okf = okf_layer()
    items = okf["props"].all()
    if category:
        items = [p for p in items if p.category == category]
    return cfg.ok([p.model_dump() for p in items])


@okf_router.get("/controls")
def okf_controls(framework: Optional[str] = None, category: Optional[str] = None, severity: Optional[str] = None):
    okf = okf_layer()
    items = okf["ckb"].all()
    if framework:
        items = [c for c in items if framework.upper() in (str(k).upper() for k in (c.frameworks or {}))]
    if category:
        items = [c for c in items if c.category == category]
    if severity:
        items = [c for c in items if c.severity == severity.upper()]
    return cfg.ok([c.model_dump() for c in items])


@okf_router.get("/controls/{control_id}")
def okf_control(control_id: str):
    okf = okf_layer()
    c = okf["ckb"].controls.get(control_id)
    if not c:
        raise HTTPException(404, f"Control {control_id} not found")
    d = c.model_dump()
    d["remediation"] = okf["rem"].index.get(control_id, {})
    return cfg.ok(d)


@okf_router.get("/crosswalk/{control_id}")
def okf_crosswalk(control_id: str):
    okf = okf_layer()
    return cfg.ok(okf["xwalk"].for_control(control_id, okf["ckb"].controls))


class DetectBody(BaseModel):
    configuration_id: str = Field(default="", max_length=64)
    config_text: str = Field(default="", max_length=5 * 1024 * 1024)   # same ceiling as a config upload


@detect_router.post("/vendor")
def detect(body: DetectBody):
    text = body.config_text
    if body.configuration_id:
        rec = db.get("configurations", body.configuration_id)
        if rec:
            text = rec["config_text"]
    if not text:
        raise HTTPException(400, "Provide configuration_id or config_text")
    return cfg.ok(vendor_detector.detect_vendor(text))
