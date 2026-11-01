"""Data-retention job: age-based, cross-tenant purges of operational data.

    run(dry_run=False) -> {"dry_run": bool, "counts": {rule: n}, "cutoffs": {...}, "skipped": [...]}

Rules (days come from app.core.config; 0 disables a rule):
  audit_log           rows older than AUDIT_LOG_RETENTION_DAYS (table is append-only; the DB trigger permits DELETE
                      only inside the transaction opened here, and the purge itself is written to the audit log)
  revoked_tokens      JWT revocations whose token has already expired (always safe)
  report_pdfs         reports.pdf bytes older than REPORT_PDF_RETENTION_DAYS (the report row/metadata is kept)
  webhook_deliveries  rows older than WEBHOOK_DELIVERY_RETENTION_DAYS
  audit_snapshots     history snapshots older than SNAPSHOT_RETENTION_DAYS (each asset's newest 30 are always kept)
  config_text         raw text of SUPERSEDED configurations (a newer one exists for the same asset), only when
                      CONFIG_RETENTION_DAYS > 0 (default off)

Called by the worker / CLI without ``org_id`` the purge is by age only and spans every tenant. Called with an
``org_id`` (the admin API passes the caller's organisation) it only touches that tenant's rows, so one tenant's
administrator can neither delete nor even count another tenant's data; the org-less ``revoked_tokens`` rule is skipped.
"""
from __future__ import annotations
import logging
from typing import Any, Dict, Optional

from app.core import auditlog
from app.core import config as cfg
from app.core import db as dbmod
from app.core import tenancy

log = logging.getLogger("sih26155.retention")

CONFIG_PURGED_MARK = "[raw configuration removed by data-retention policy]"
SNAPSHOT_KEEP_LAST = 30
_LOCK_KEY = 74_110_011      # advisory lock so concurrent workers do not run the same purge


def _snap_pred() -> str:
    return ("created_at < now() - make_interval(days => %s) AND snapshot_id NOT IN ("
            " SELECT snapshot_id FROM (SELECT snapshot_id, row_number() OVER (PARTITION BY org_id, asset_id "
            " ORDER BY created_at DESC) rn FROM audit_snapshots) r WHERE rn <= %s)")


def _rules() -> Dict[str, Dict[str, Any]]:
    """rule -> {days, count_sql, run_sql, params}. SQL is static; only days / constants are bound."""
    cfg_pred = ("created_at < now() - make_interval(days => %s) AND config_text <> %s AND EXISTS ("
                " SELECT 1 FROM configurations n WHERE n.asset_id = configurations.asset_id "
                " AND n.org_id = configurations.org_id AND n.created_at > configurations.created_at)")
    return {
        "audit_log": {"days": cfg.AUDIT_LOG_RETENTION_DAYS, "table": "audit_log",
                      "where": "ts < now() - make_interval(days => %s)", "verb": "DELETE FROM", "params": lambda d: (d,)},
        "revoked_tokens": {"days": None, "table": "revoked_tokens", "where": "expires_at < now()",
                           "verb": "DELETE FROM", "params": lambda d: ()},
        "report_pdfs": {"days": cfg.REPORT_PDF_RETENTION_DAYS, "table": "reports",
                        "where": "pdf IS NOT NULL AND created_at < now() - make_interval(days => %s)",
                        "verb": "UPDATE", "set": "pdf = NULL", "params": lambda d: (d,)},
        "webhook_deliveries": {"days": cfg.WEBHOOK_DELIVERY_RETENTION_DAYS, "table": "webhook_deliveries",
                               "where": "created_at < now() - make_interval(days => %s)",
                               "verb": "DELETE FROM", "params": lambda d: (d,)},
        "audit_snapshots": {"days": cfg.SNAPSHOT_RETENTION_DAYS, "table": "audit_snapshots", "where": _snap_pred(),
                            "verb": "DELETE FROM", "params": lambda d: (d, SNAPSHOT_KEEP_LAST)},
        "config_text": {"days": cfg.CONFIG_RETENTION_DAYS, "table": "configurations", "where": cfg_pred,
                        "verb": "UPDATE", "set": "config_text = %s",
                        "set_params": (CONFIG_PURGED_MARK,), "params": lambda d: (d, CONFIG_PURGED_MARK)},
    }


def run(dry_run: bool = False, org_id: Optional[str] = None) -> Dict[str, Any]:
    # the platform-wide purge (org_id None) is system work; a tenant-scoped purge keeps the caller's own scope
    if org_id is None:
        with tenancy.unscoped():
            return _run(dry_run, org_id)
    return _run(dry_run, org_id)


def _run(dry_run: bool, org_id: Optional[str]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    cutoffs: Dict[str, int] = {}
    skipped: list[str] = []
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("SELECT pg_try_advisory_xact_lock(%s)", (_LOCK_KEY,))
        if not cur.fetchone()[0]:
            return {"dry_run": dry_run, "counts": {}, "cutoffs": {}, "skipped": ["another retention run is in progress"]}
        cur.execute("SELECT set_config('app.audit_retention', 'on', true)")     # transaction-local DELETE permit
        for name, r in _rules().items():
            days = r["days"]
            if days is not None and int(days) <= 0:
                skipped.append(name)
                continue
            where = r["where"]
            extra: tuple = ()
            if org_id is not None:
                if r["table"] == "revoked_tokens":          # no org column: global housekeeping only
                    skipped.append(name)
                    continue
                where = f"({where}) AND org_id = %s"
                extra = (org_id,)
            if days is not None:
                cutoffs[name] = int(days)
            params = tuple(r["params"](days)) + extra
            if dry_run:
                cur.execute(f"SELECT count(*) FROM {r['table']} WHERE {where}", params)
                counts[name] = cur.fetchone()[0]
            elif r["verb"] == "DELETE FROM":
                cur.execute(f"DELETE FROM {r['table']} WHERE {where}", params)
                counts[name] = cur.rowcount
            else:
                cur.execute(f"UPDATE {r['table']} SET {r['set']} WHERE {where}",
                            tuple(r.get("set_params", ())) + params)
                counts[name] = cur.rowcount
    out = {"dry_run": dry_run, "counts": counts, "cutoffs": cutoffs, "skipped": skipped}
    if not dry_run:
        log.info("retention: %s", counts)
        auditlog.record("retention.purge", actor={"id": "system:retention", "email": None, "role": "SYSTEM"},
                        org_id=org_id or cfg.DEFAULT_ORG_ID,
                        detail={"counts": counts, "retention_days": cutoffs, "skipped": skipped,
                                "cross_tenant": org_id is None})
    return out
