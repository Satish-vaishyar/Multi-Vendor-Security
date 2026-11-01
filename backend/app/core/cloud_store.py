"""Persistence for the cloud security module (docs/CLOUD_MODULE_RTM.md, S04/S14). Own tables only (migrate_017.sql); every
statement is parameterised and filtered by the caller's organisation, so one tenant can never read or overwrite another's rows.
Cloud findings are never written to the existing `findings` table, so existing dashboards and reports are unchanged."""
from __future__ import annotations
import hashlib
import json
from typing import Any, Dict, List, Optional

from app.core import db as dbmod
from app.core import tenancy

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_STATES = ("PASS_STATIC", "FAIL_STATIC", "UNKNOWN_STATIC", "NOT_APPLICABLE", "PASS_LIVE", "FAIL_LIVE", "UNKNOWN_LIVE", "CONFLICT")
MAX_PAGE = 200


def _id(prefix: str, *parts: str) -> str:
    return prefix + "-" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:24]


def _j(value: Any):
    from psycopg.types.json import Jsonb
    return Jsonb(json.loads(json.dumps(value, default=str)))


def save_report(scan_id: str, report: Dict[str, Any], created_by: str) -> None:
    """Persist a completed (or refused) scan report. Idempotent per scan_id; refuses to touch another organisation's scan."""
    org = tenancy.current_org()
    cov = report.get("coverage") or {}
    status = "COMPLETED" if report.get("status") == "COMPLETED" else "FAILED"
    inp = report.get("input") or {}
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO cloud_scans (scan_id, org_id, mode, status, file_name, content_sha256, size_bytes, providers, formats, summary,"
            " coverage, rule_pack_version, engine_versions, error, created_by, completed_at) VALUES"
            " (%s,%s,'static',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, now())"
            " ON CONFLICT (scan_id) DO UPDATE SET status=EXCLUDED.status, summary=EXCLUDED.summary, coverage=EXCLUDED.coverage,"
            " error=EXCLUDED.error, completed_at=now() WHERE cloud_scans.org_id = EXCLUDED.org_id",
            [scan_id, org, status, str(inp.get("filename", ""))[:255], inp.get("sha256"), inp.get("size_bytes"),
             _j(cov.get("providers", [])), _j(sorted((cov.get("formats") or {}).keys())),
             _j({**(report.get("summary") or {}), "statement": report.get("statement", "")}), _j(cov),
             report.get("rule_pack_version"), _j({}), (report.get("error") or None), created_by[:200]])
        if cur.rowcount == 0:
            raise PermissionError("scan belongs to another organization")
        keys: Dict[str, str] = {}
        for r in report.get("resources") or []:
            rid = _id("CRES", org, scan_id, str(r.get("address")))
            keys[str(r.get("address"))] = rid
            cur.execute(
                "INSERT INTO cloud_resources (resource_id, org_id, scan_id, resource_key, provider, service, resource_type, logical_name,"
                " properties, relationships, source, evidence_mode, confidence, unknown_fields) VALUES"
                " (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'static',%s,%s) ON CONFLICT (resource_id) DO NOTHING",
                [rid, org, scan_id, str(r.get("address"))[:1000], str(r.get("provider") or "unknown"), r.get("service"),
                 str(r.get("resource_type") or "unknown"), r.get("logical_name"), _j(r.get("properties") or {}),
                 _j(r.get("relationships") or []), _j(r.get("source") or {}), float(r.get("confidence", 1.0)),
                 _j(r.get("unknown_fields") or [])])
        for f in report.get("findings") or []:
            sev = f.get("severity") if f.get("severity") in _SEVERITIES else "INFO"
            state = f.get("evidence_state") if f.get("evidence_state") in _STATES else "UNKNOWN_STATIC"
            fid = _id("CFND", org, scan_id, str(f.get("control_id")), str(f.get("resource_address")), str((f.get("source") or {}).get("file")))
            extra = {**(f.get("source") or {}), "resource_address": f.get("resource_address"), "provider": f.get("provider"),
                     "resource_type": f.get("resource_type"), "notes": f.get("notes") or []}
            cur.execute(
                "INSERT INTO cloud_findings (finding_id, org_id, scan_id, resource_id, rule_id, rule_version, title, severity, evidence_state,"
                " engine, observed, source, frameworks, remediation, dedupe_key) VALUES"
                " (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (finding_id) DO NOTHING",
                [fid, org, scan_id, keys.get(str(f.get("resource_address"))), str(f.get("control_id"))[:100], f.get("rule_version"),
                 str(f.get("title"))[:500], sev, state, str(f.get("engine") or "orbit")[:50], _j(f.get("evidence") or []), _j(extra),
                 _j(f.get("frameworks") or []), _j(f.get("remediation") or {}), f.get("dedupe_key")])


def list_scans(limit: int = 50) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit), MAX_PAGE))
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT scan_id, status, file_name, providers, summary, rule_pack_version, created_by, created_at, completed_at"
                    " FROM cloud_scans WHERE org_id=%s ORDER BY created_at DESC LIMIT %s", [tenancy.current_org(), limit])
        cols = [d.name for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT scan_id, status, file_name, content_sha256, size_bytes, providers, formats, summary, coverage,"
                    " rule_pack_version, error, created_by, created_at, completed_at FROM cloud_scans WHERE scan_id=%s AND org_id=%s",
                    [scan_id, tenancy.current_org()])
        row = cur.fetchone()
        return dict(zip([d.name for d in cur.description], row)) if row else None


def list_findings(scan_id: str, state: Optional[str] = None, severity: Optional[str] = None,
                  page: int = 1, size: int = 50) -> Dict[str, Any]:
    size = max(1, min(int(size), MAX_PAGE))
    page = max(1, int(page))
    where, args = ["scan_id=%s", "org_id=%s"], [scan_id, tenancy.current_org()]
    if state in _STATES:
        where.append("evidence_state=%s")
        args.append(state)
    if severity in _SEVERITIES:
        where.append("severity=%s")
        args.append(severity)
    clause = " AND ".join(where)
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(f"SELECT count(*) FROM cloud_findings WHERE {clause}", args)
        total = cur.fetchone()[0]
        cur.execute(f"SELECT finding_id, rule_id, rule_version, title, severity, evidence_state, engine, observed, source, frameworks,"
                    f" remediation, dedupe_key FROM cloud_findings WHERE {clause}"
                    f" ORDER BY array_position(ARRAY['CRITICAL','HIGH','MEDIUM','LOW','INFO'], severity), rule_id, finding_id"
                    f" LIMIT %s OFFSET %s", args + [size, (page - 1) * size])
        cols = [d.name for d in cur.description]
        return {"items": [dict(zip(cols, r)) for r in cur.fetchall()], "total": total, "page": page, "size": size}


def report_for_export(scan_id: str) -> Optional[Dict[str, Any]]:
    """Rebuild the scanner-report shape the exporters expect from the stored rows (organisation-scoped)."""
    scan = get_scan(scan_id)
    if not scan:
        return None
    out: List[Dict[str, Any]] = []
    page = 1
    while True:
        chunk = list_findings(scan_id, page=page, size=MAX_PAGE)
        for f in chunk["items"]:
            src = dict(f.get("source") or {})
            out.append({"control_id": f["rule_id"], "title": f["title"], "severity": f["severity"], "evidence_state": f["evidence_state"],
                        "engine": f["engine"], "provider": src.get("provider"), "resource_type": src.get("resource_type"),
                        "resource_address": src.get("resource_address"), "source": src, "remediation": f.get("remediation") or {},
                        "evidence": f.get("observed") or []})
        if page * MAX_PAGE >= chunk["total"]:
            break
        page += 1
    return {"rule_pack_version": scan.get("rule_pack_version"), "findings": out}
