"""Dashboard aggregates computed entirely in SQL (GROUP BY / AVG / COUNT).

Nothing here fetches findings or audit blobs into Python: every number is a
fleet-wide aggregate, org-scoped through persist._org_clause, and cached for a
few seconds per organisation (TTL only; no event invalidation).

Compliance numbers use the LATEST audit per asset, so re-auditing a device does
not weight it more than a device audited once.
"""
from __future__ import annotations
import os
import threading
import time
from typing import Any, Callable, Dict, List, Tuple

from app.core import db as dbmod
from app.core import persist as db
from app.core import tenancy

TTL_SECONDS = float(os.getenv("DASHBOARD_CACHE_TTL", "5"))
TREND_AUDITS = 10
TOP_CONTROLS = 10

_NUM = r"'^-?[0-9]+(\.[0-9]+)?$'"
_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_LOCK = threading.Lock()
_clock: Callable[[], float] = time.monotonic     # patched in tests


def clear_cache() -> None:
    with _LOCK:
        _CACHE.clear()


def _org_key() -> str:
    return "*" if tenancy.is_unscoped() else tenancy.current_org()


def _where(alias: str, *extra: str) -> Tuple[str, List[Any]]:
    oc, ov = db._org_clause(alias)
    parts = list(extra) + oc
    return (f"WHERE {' AND '.join(parts)}" if parts else ""), ov


def _compute() -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    with dbmod.get_conn() as conn:
        cur = conn.cursor()

        def q(sql: str, params: List[Any]) -> list:
            cur.execute(sql, params)
            return cur.fetchall()

        # ---- assets
        w, p = _where("", "UPPER(status)='ACTIVE'")
        vendors = {str(v): int(n) for v, n in q(
            "SELECT COALESCE(NULLIF(LOWER(vendor),''),'unknown'), COUNT(*) "
            f"FROM assets {w} GROUP BY 1", p)}
        active = sum(vendors.values())
        w, p = _where("f.", "UPPER(f.status)='FAIL'", "UPPER(f.severity) IN ('CRITICAL','HIGH')",
                      "UPPER(a.status)='ACTIVE'")
        oc_a, ov_a = db._org_clause("a.")
        w2 = w + (" AND " + " AND ".join(oc_a) if oc_a else "")
        at_risk = int(q("SELECT COUNT(DISTINCT f.asset_id) FROM findings f "
                        f"JOIN assets a ON a.asset_id=f.asset_id {w2}", p + ov_a)[0][0])
        out["assets"] = {"total": active, "healthy": active - at_risk, "at_risk": at_risk}

        # ---- findings (one GROUP BY, summed in Python over <= a few dozen groups)
        w, p = _where("")
        groups = q("SELECT UPPER(severity), UPPER(status), LOWER(engine), COUNT(*) "
                   f"FROM findings {w} GROUP BY 1,2,3", p)
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        cve = {"critical": 0, "high": 0}
        by_engine: Dict[str, Dict[str, int]] = {}
        total_f = 0
        for s_, st, eng, n in groups:
            n = int(n)
            total_f += n
            if st == "FAIL":
                if (s_ or "").lower() in sev:
                    sev[s_.lower()] += n
                e = by_engine.setdefault(eng or "unknown", {"fail": 0, "total": 0})
                e["fail"] += n
            by_engine.setdefault(eng or "unknown", {"fail": 0, "total": 0})["total"] += n
            if eng == "cve" and (s_ or "").lower() in cve:
                cve[s_.lower()] += n
        out["findings"] = sev
        out["cve"] = cve
        out["by_severity"] = dict(sev)
        out["by_engine"] = by_engine
        out["totals"] = {"findings": total_f, "failed": sum(e["fail"] for e in by_engine.values())}

        # ---- findings by vendor (join to assets)
        w, p = _where("f.", "UPPER(f.status)='FAIL'")
        oc_a, ov_a = db._org_clause("a.")
        w3 = w + (" AND " + " AND ".join(oc_a) if oc_a else "")
        fv = {str(v): int(n) for v, n in q(
            "SELECT COALESCE(NULLIF(LOWER(a.vendor),''),'unknown'), COUNT(*) FROM findings f "
            f"JOIN assets a ON a.asset_id=f.asset_id {w3} GROUP BY 1", p + ov_a)}
        out["by_vendor"] = {v: {"assets": vendors.get(v, 0), "failed_findings": fv.get(v, 0)}
                            for v in sorted(set(vendors) | set(fv))}

        # ---- compliance from the latest audit per asset
        w, p = _where("")
        latest = (f"(SELECT DISTINCT ON (COALESCE(asset_id, audit_id)) audit_id, summary, by_framework, pqc, created_at "
                  f"FROM audits {w} ORDER BY COALESCE(asset_id, audit_id), created_at DESC) l")
        score = f"CASE WHEN (l.summary->>'compliance_score') ~ {_NUM} THEN (l.summary->>'compliance_score')::float END"
        r = q(f"SELECT AVG({score}), COUNT(*) FROM {latest}", p)[0]
        out["compliance"] = {"overall": round(float(r[0]), 1) if r[0] is not None else 0.0}
        audits_n = int(r[1])
        dist = {int(b): int(n) for b, n in q(
            f"SELECT LEAST(FLOOR(s/20), 4)::int, COUNT(*) FROM (SELECT {score} AS s FROM {latest}) x "
            "WHERE s IS NOT NULL GROUP BY 1", p)}
        labels = ["0-19", "20-39", "40-59", "60-79", "80-100"]
        out["score_distribution"] = [{"range": lb, "count": dist.get(i, 0)} for i, lb in enumerate(labels)]
        fw = q("SELECT k, AVG((v->>'compliance_score')::float) FROM "
               f"(SELECT (jsonb_each(CASE WHEN jsonb_typeof(l.by_framework)='object' THEN l.by_framework "
               f"ELSE '{{}}'::jsonb END)).* FROM {latest}) t(k, v) "
               f"WHERE jsonb_typeof(v)='object' AND (v->>'compliance_score') ~ {_NUM} GROUP BY k", p)
        out["frameworks"] = {str(k): {"score": round(float(a), 1)} for k, a in fw}
        pq = q(f"SELECT AVG(CASE WHEN (l.pqc->>'readiness_score') ~ {_NUM} THEN (l.pqc->>'readiness_score')::float END) "
               f"FROM {latest}", p)[0][0]
        out["pqc"] = {"audits": audits_n, "readiness": round(float(pq), 1) if pq is not None else 0.0}

        # ---- trend over the most recent audits (chronological)
        w, p = _where("")
        rows = q("SELECT audit_id, asset_id, created_at, "
                 f"CASE WHEN (summary->>'compliance_score') ~ {_NUM} THEN (summary->>'compliance_score')::float END "
                 f"FROM audits {w} ORDER BY created_at DESC, audit_id DESC LIMIT {TREND_AUDITS}", p)
        out["trend"] = [{"audit_id": a, "asset_id": b, "created_at": c.isoformat() if c else None,
                         "compliance_score": round(float(s), 1) if s is not None else None}
                        for a, b, c, s in reversed(rows)]

        # ---- top failing controls
        w, p = _where("", "UPPER(status)='FAIL'", "control_id IS NOT NULL", "control_id <> ''")
        out["top_failing_controls"] = [
            {"control_id": c, "title": t, "failures": int(n), "assets": int(na), "severity": s}
            for c, t, n, na, s in q(
                "SELECT control_id, MAX(title), COUNT(*), COUNT(DISTINCT asset_id), "
                f"MODE() WITHIN GROUP (ORDER BY severity) FROM findings {w} "
                f"GROUP BY control_id ORDER BY COUNT(*) DESC, control_id LIMIT {TOP_CONTROLS}", p)]

    out["training"] = {"pending": db.count("training", status="PENDING")}
    return out


def summary() -> Dict[str, Any]:
    """Cached (per org, TTL only) dashboard aggregates."""
    key = _org_key()
    now = _clock()
    with _LOCK:
        hit = _CACHE.get(key)
        if hit and hit[0] > now:
            return hit[1]
    data = _compute()
    with _LOCK:
        _CACHE[key] = (now + TTL_SECONDS, data)
    return data
