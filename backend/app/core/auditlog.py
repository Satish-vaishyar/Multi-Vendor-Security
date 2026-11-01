"""Append-only audit trail (who did what, when, from where).

Rows go to the ``audit_log`` table, which has a trigger that rejects UPDATE and
DELETE. Writing the log must never break the request: failures are logged and
swallowed (the application log still has them).
"""
from __future__ import annotations
import logging
from typing import Any, Dict, Optional

from app.core import config as cfg
from app.core import db as dbmod

log = logging.getLogger("sih26155")

# GETs that are sensitive enough to record (everything non-GET is always recorded).
SENSITIVE_GET_PREFIXES = (
    "/api/v1/reports/",        # report downloads
    "/api/v1/configurations/",  # reading device configs
    "/api/v1/admin/",
)


def should_log(method: str, path: str) -> bool:
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return True
    return method == "GET" and path.startswith(SENSITIVE_GET_PREFIXES)


def record(action: str, *, actor: Optional[Dict[str, Any]] = None, method: str = "",
           path: str = "", status: Optional[int] = None, ip: str = "",
           request_id: str = "", detail: Optional[Dict[str, Any]] = None,
           org_id: Optional[str] = None) -> None:
    if not dbmod.is_configured():
        return
    try:
        from psycopg.types.json import Jsonb
        actor = actor or {}
        with dbmod.get_conn() as conn:
            cur = conn.cursor()  # type: ignore[attr-defined]
            cur.execute(
                "INSERT INTO audit_log (org_id, actor_id, actor_email, role, action, method, path,"
                " status, ip, request_id, detail) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (org_id or actor.get("org_id") or cfg.DEFAULT_ORG_ID, actor.get("id"), actor.get("email"),
                 actor.get("role"), action, method, path[:500], status, ip, request_id,
                 Jsonb(detail or {})))
    except Exception as e:  # never break the request because the trail failed
        log.error("audit log write failed (%s %s): %s", method, path, e)
