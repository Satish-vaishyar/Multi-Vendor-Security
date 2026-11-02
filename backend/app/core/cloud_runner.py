"""Recurring cloud scans (docs/CLOUD_MODULE_RTM.md S23). ``python -m app.cloud_scheduler`` runs ``tick`` in a loop; it is a separate
process (see docker-compose.cloud.yml) so the existing worker and its schedules are not touched. A run re-submits the kept bytes to
the sandboxed scanner through the same code path as an upload; the backend still never parses or executes them."""
from __future__ import annotations
import logging
from typing import Any, Dict, Optional, Tuple

from fastapi import HTTPException

from app.core import cloud_ext as ext
from app.core import tenancy

log = logging.getLogger("sih26155")
SYSTEM_ACTOR = {"email": "cloud-scheduler", "id": "cloud-scheduler", "role": "AUDITOR"}


def run_source(source_id: str, who: str, actor: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """Run one kept file now (org already bound). Returns (status, scan_id); never raises, so one bad schedule cannot stop the rest."""
    from app.api.v1 import cloud
    try:
        src = ext.load_source(source_id)
        if not src:
            return "SOURCE_MISSING", None
        scan_id, report = cloud.run_scan(src["data"], str(src["file_name"] or "scheduled"), who, actor)
        return ("COMPLETED" if report.get("status") == "COMPLETED" else "FAILED"), scan_id
    except HTTPException as e:
        return f"ERROR: {e.detail}"[:100], None
    except Exception as e:  # noqa: BLE001 - isolate each run; details stay in the log, not in the stored status
        log.exception("recurring cloud scan failed")
        return f"ERROR: {type(e).__name__}", None


def tick(limit: int = 20) -> int:
    """Fire every due recurring scan once (cross-tenant, safe in several processes). Returns how many completed."""
    from app.api.v1 import cloud
    if not cloud.enabled():
        return 0
    done = 0
    for row in ext.claim_due(limit):
        with tenancy.use_org(row["org_id"]):
            status, scan_id = run_source(row["source_id"], f"scheduler:{row.get('created_by') or 'unknown'}"[:200], SYSTEM_ACTOR)
            ext.record_run(row["schedule_id"], scan_id, status)
        done += status == "COMPLETED"
    ext.purge_expired_sources()
    return done
