"""Audit history: snapshots, change detection (drift), finding age, trends, and config diffs.

Every completed audit run appends one compact snapshot (``audit_snapshots``). Comparing two snapshots of the
same asset answers the questions an auditor actually asks: what is new, what was fixed, what has been open
for how long, did the score move because the *config* changed or because the *knowledge* (CVE DB, control
packs) changed.
"""
from __future__ import annotations
import difflib
import hashlib
import re
import time
import uuid
from typing import Any, Dict, List, Optional

from psycopg.types.json import Jsonb

from app.core import config as cfg
from app.core import db as dbmod
from app.core import persist as db
from app.core import tenancy
from app.core.redact import redact_secrets

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
MAX_DIFF_LINES = 400
# difflib's SequenceMatcher is super-linear on repetitive input; two hostile 5 MB configs could pin a worker for
# minutes. Above this many lines per side the diff is skipped (the summary + hashes are still returned).
MAX_DIFF_INPUT_LINES = 20_000
VERSION_KEYS = ("okf", "cve_kb", "control_pack", "mapping_registry", "pqc_rules", "parser")


# ------------------------------------------------------------------------------- keys
def finding_key(f: Dict[str, Any]) -> str:
    """Stable identity of a finding ACROSS audit runs (finding_id changes with the audit id)."""
    eng = str(f.get("engine") or f.get("type") or "").lower()
    src = f.get("source") if isinstance(f.get("source"), dict) else {}
    ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
    if eng == "compliance":
        return f"compliance:{f.get('control_id')}"
    if eng == "cve":
        cve = src.get("cve") or (_CVE_RE.search(str(f.get("title") or "")) or [None])[0]
        return f"cve:{str(cve or f.get('title') or '?').upper()}"
    if eng == "pqc":
        obs = ev.get("observed") if isinstance(ev.get("observed"), dict) else {}
        return f"pqc:{obs.get('algorithm', '?')}:{obs.get('protocol', '')}"
    return f"{eng}:{src.get('analytics', '')}:{ev.get('property', '')}"


def compact_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Only what is NOT passing is stored: that is enough to detect new / resolved / aging findings."""
    out = []
    for f in findings:
        st = str(f.get("status") or "").upper()
        if st in ("FAIL", "UNKNOWN"):
            out.append({"k": finding_key(f), "st": st, "sev": str(f.get("severity") or "UNKNOWN").upper(),
                        "t": str(f.get("title") or "")[:140], "e": str(f.get("engine") or f.get("type") or "").lower()})
    return out


# ---------------------------------------------------------------------------- recording
def _counts(record: Dict[str, Any]) -> Dict[str, Any]:
    s = record.get("summary") or {}
    cve = (s.get("cve") or {})
    return {"failed": s.get("failed", 0), "critical": s.get("CRITICAL", 0), "high": s.get("HIGH", 0),
            "medium": s.get("MEDIUM", 0), "low": s.get("LOW", 0), "unknown": s.get("unknown", 0),
            "assessed": s.get("assessed", 0), "assumed": s.get("assumed", 0), "vulnerable": cve.get("vulnerable", 0),
            "pqc_readiness": s.get("pqc_readiness"), "security_risk": s.get("security_risk")}


def diff_findings(before: List[Dict[str, Any]], after: List[Dict[str, Any]]) -> Dict[str, Any]:
    b = {x["k"]: x for x in before if x["st"] == "FAIL"}
    a = {x["k"]: x for x in after if x["st"] == "FAIL"}
    new = [a[k] for k in a if k not in b]
    resolved = [b[k] for k in b if k not in a]
    worse = [a[k] for k in a if k in b and _SEV_ORDER.get(a[k]["sev"], 9) < _SEV_ORDER.get(b[k]["sev"], 9)]
    key = lambda x: (_SEV_ORDER.get(x["sev"], 9), x["k"])  # noqa: E731
    return {"new": sorted(new, key=key), "resolved": sorted(resolved, key=key), "severity_increased": sorted(worse, key=key),
            "unchanged": len(set(a) & set(b))}


def record_snapshot(record: Dict[str, Any], trigger: str = "manual") -> Dict[str, Any]:
    """Append a snapshot for a finished audit and compute the diff against the asset's previous one."""
    asset_id = str(record.get("asset_id") or "")
    findings = compact_findings(record.get("findings") or [])
    prev = latest(asset_id)
    changes: Dict[str, Any] = {}
    if prev:
        d = diff_findings(prev["findings"], findings)
        prev_ver, cur_ver = prev.get("versions") or {}, record.get("versions") or {}
        changed_knowledge = [k for k in VERSION_KEYS if prev_ver.get(k) != cur_ver.get(k)]
        changes = {"previous_snapshot_id": prev["snapshot_id"], "new": len(d["new"]), "resolved": len(d["resolved"]),
                   "severity_increased": len(d["severity_increased"]), "unchanged": d["unchanged"],
                   "new_critical_high": sum(1 for x in d["new"] if x["sev"] in ("CRITICAL", "HIGH")),
                   "config_changed": prev.get("config_sha256") != record.get("config_sha256"),
                   "knowledge_changed": changed_knowledge,
                   "score_delta": round(float((record.get("summary") or {}).get("compliance_score") or 0)
                                        - float(prev.get("compliance_score") or 0), 1)}
    sid = "SNP-" + uuid.uuid4().hex[:12].upper()
    s = record.get("summary") or {}
    with dbmod.get_conn() as conn:
        conn.cursor().execute(  # type: ignore[attr-defined]
            "INSERT INTO audit_snapshots (snapshot_id, org_id, asset_id, audit_id, configuration_id, config_sha256, trigger, "
            "compliance_score, coverage_pct, counts, versions, findings, changes) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (sid, tenancy.current_org(), asset_id, record.get("audit_id"), record.get("configuration_id"),
             record.get("config_sha256"), trigger, s.get("compliance_score"), s.get("coverage_pct"),
             Jsonb(_counts(record)), Jsonb({k: record.get("versions", {}).get(k) for k in VERSION_KEYS}),
             Jsonb(findings), Jsonb(changes)))
    return {"snapshot_id": sid, **changes}


# ------------------------------------------------------------------------------ reading
_COLS = ("snapshot_id, asset_id, audit_id, configuration_id, config_sha256, trigger, compliance_score, coverage_pct, "
         "counts, versions, findings, changes, extract(epoch from created_at) AS created_at")


def _rows(cur) -> List[Dict[str, Any]]:
    cols = [d[0] for d in cur.description]
    out = []
    for r in cur.fetchall():
        d = dict(zip(cols, r))
        d["created_at"] = float(d["created_at"])
        out.append(d)
    return out


def latest(asset_id: str) -> Optional[Dict[str, Any]]:
    rows = list_snapshots(asset_id, limit=1)
    return rows[0] if rows else None


def list_snapshots(asset_id: str, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(f"SELECT {_COLS} FROM audit_snapshots WHERE org_id=%s AND asset_id=%s ORDER BY created_at DESC LIMIT %s OFFSET %s",
                    (tenancy.current_org(), asset_id, limit, offset))
        return _rows(cur)


def get_snapshot(snapshot_id: str) -> Optional[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(f"SELECT {_COLS} FROM audit_snapshots WHERE org_id=%s AND snapshot_id=%s", (tenancy.current_org(), snapshot_id))
        rows = _rows(cur)
        return rows[0] if rows else None


def summary_view(s: Dict[str, Any]) -> Dict[str, Any]:
    """Snapshot without the (large) finding list, for charts and tables."""
    return {k: s[k] for k in ("snapshot_id", "audit_id", "configuration_id", "config_sha256", "trigger", "compliance_score",
                              "coverage_pct", "counts", "versions", "changes", "created_at")}


def finding_ages(asset_id: str, current: List[Dict[str, Any]], now: Optional[float] = None) -> Dict[str, float]:
    """Days each currently-failing finding has been continuously failing (first snapshot of the unbroken streak)."""
    now = now or time.time()
    snaps = list_snapshots(asset_id, limit=500)           # newest first
    ages: Dict[str, float] = {}
    for f in current:
        if f["st"] != "FAIL":
            continue
        since = None
        for s in snaps:
            if any(x["k"] == f["k"] and x["st"] == "FAIL" for x in s["findings"]):
                since = s["created_at"]
            else:
                break                                       # streak broken: it was fixed in between
        ages[f["k"]] = round((now - since) / 86400, 1) if since else 0.0
    return ages


def compare(asset_id: str, from_id: str, to_id: str) -> Optional[Dict[str, Any]]:
    a, b = get_snapshot(from_id), get_snapshot(to_id)
    if not a or not b or a["asset_id"] != asset_id or b["asset_id"] != asset_id:
        return None
    d = diff_findings(a["findings"], b["findings"])
    ages = finding_ages(asset_id, b["findings"])
    for x in d["new"] + d["severity_increased"]:
        x["age_days"] = 0.0
    persisting = [dict(x, age_days=ages.get(x["k"], 0.0)) for x in b["findings"]
                  if x["st"] == "FAIL" and any(y["k"] == x["k"] and y["st"] == "FAIL" for y in a["findings"])]
    persisting.sort(key=lambda x: (-x["age_days"], _SEV_ORDER.get(x["sev"], 9)))
    return {"asset_id": asset_id, "from": summary_view(a), "to": summary_view(b), "new": d["new"], "resolved": d["resolved"],
            "severity_increased": d["severity_increased"], "persisting": persisting[:200],
            "score_delta": round(float(b["compliance_score"] or 0) - float(a["compliance_score"] or 0), 1),
            "config_changed": a["config_sha256"] != b["config_sha256"],
            "knowledge_changed": [k for k in VERSION_KEYS if (a["versions"] or {}).get(k) != (b["versions"] or {}).get(k)]}


def trend(days: int = 90, asset_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Per day: average compliance score of each asset's LATEST snapshot that day, plus failing totals."""
    clauses, vals = ["org_id=%s", "created_at >= now() - make_interval(days => %s)"], [tenancy.current_org(), days]
    if asset_id:
        clauses.append("asset_id=%s")
        vals.append(asset_id)
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(
            "SELECT day, count(*) AS assets, round(avg(compliance_score)::numeric,1) AS score, "
            "sum((counts->>'critical')::int) AS critical, sum((counts->>'high')::int) AS high, "
            "sum((counts->>'failed')::int) AS failed, round(avg(coverage_pct)::numeric,1) AS coverage FROM ("
            " SELECT DISTINCT ON (asset_id, date_trunc('day', created_at)) date_trunc('day', created_at) AS day, "
            f" asset_id, compliance_score, coverage_pct, counts FROM audit_snapshots WHERE {' AND '.join(clauses)} "
            " ORDER BY asset_id, date_trunc('day', created_at), created_at DESC) x GROUP BY day ORDER BY day", vals)
        return [{"day": r[0].date().isoformat(), "assets": r[1], "score": float(r[2] or 0), "critical": r[3] or 0,
                 "high": r[4] or 0, "failed": r[5] or 0, "coverage_pct": float(r[6] or 0)} for r in cur.fetchall()]


def recent_changes(since_days: int = 7, limit: int = 100, only_notable: bool = True) -> List[Dict[str, Any]]:
    """Feed of what changed across the estate: new critical/high findings, regressions, big score moves."""
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(
            "SELECT s.snapshot_id, s.asset_id, a.data->>'name', s.audit_id, s.trigger, s.compliance_score, s.changes, "
            "extract(epoch from s.created_at) FROM audit_snapshots s LEFT JOIN assets a ON a.asset_id = s.asset_id "
            "WHERE s.org_id=%s AND s.created_at >= now() - make_interval(days => %s) AND s.changes <> '{}'::jsonb "
            "ORDER BY s.created_at DESC LIMIT %s", (tenancy.current_org(), since_days, limit * 3))
        rows = cur.fetchall()
    out = []
    for sid, asset, name, audit, trig, score, ch, ts in rows:
        notable = ch.get("new_critical_high", 0) > 0 or ch.get("severity_increased", 0) > 0 or abs(ch.get("score_delta", 0)) >= 5
        if only_notable and not notable:
            continue
        out.append({"snapshot_id": sid, "asset_id": asset, "asset_name": name, "audit_id": audit, "trigger": trig,
                    "compliance_score": score, "changes": ch, "created_at": float(ts)})
        if len(out) >= limit:
            break
    return out


# -------------------------------------------------------------------------- config diff
def config_diff(cfg_id_a: str, cfg_id_b: str) -> Optional[Dict[str, Any]]:
    """Unified diff of two stored configurations with secrets masked. Secret changes are counted, never shown."""
    ca, cb = db.get("configurations", cfg_id_a), db.get("configurations", cfg_id_b)
    if not ca or not cb:
        return None
    raw_a, raw_b = ca["config_text"].splitlines(), cb["config_text"].splitlines()
    sha = {"from": hashlib.sha256(ca["config_text"].encode()).hexdigest(),
           "to": hashlib.sha256(cb["config_text"].encode()).hexdigest()}
    if max(len(raw_a), len(raw_b)) > MAX_DIFF_INPUT_LINES:
        return {"from": cfg_id_a, "to": cfg_id_b, "added": None, "removed": None, "secret_lines_changed": None,
                "identical": sha["from"] == sha["to"], "truncated": True, "diff": [], "sha256": sha,
                "skipped": f"configuration too large to diff (more than {MAX_DIFF_INPUT_LINES} lines)"}
    red_a, red_b = [redact_secrets(x) for x in raw_a], [redact_secrets(x) for x in raw_b]
    hunks = list(difflib.unified_diff(red_a, red_b, fromfile=cfg_id_a, tofile=cfg_id_b, n=2, lineterm=""))
    added = sum(1 for h in hunks if h.startswith("+") and not h.startswith("+++"))
    removed = sum(1 for h in hunks if h.startswith("-") and not h.startswith("---"))
    # A secret line (password / community / key) that exists in both versions with the same masked form but a
    # different real value was CHANGED. Only the count is reported - never the values.
    def secret_lines(raw: List[str]) -> Dict[str, set]:
        d: Dict[str, set] = {}
        for x in raw:
            masked = redact_secrets(x)
            if masked != x:
                d.setdefault(masked, set()).add(x)
        return d

    sa, sb = secret_lines(raw_a), secret_lines(raw_b)
    secret_changes = sum(1 for k in sa.keys() & sb.keys() if sa[k] != sb[k])
    truncated = len(hunks) > MAX_DIFF_LINES
    return {"from": cfg_id_a, "to": cfg_id_b, "added": added, "removed": removed, "secret_lines_changed": secret_changes,
            "identical": red_a == red_b and raw_a == raw_b, "truncated": truncated, "diff": hunks[:MAX_DIFF_LINES],
            "sha256": sha}


def purge(older_than_days: Optional[int] = None, keep_last: int = 30) -> int:
    """Drop snapshots older than retention, always keeping each asset's most recent `keep_last`."""
    days = older_than_days or cfg.SNAPSHOT_RETENTION_DAYS
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute(
            "DELETE FROM audit_snapshots WHERE created_at < now() - make_interval(days => %s) AND snapshot_id NOT IN ("
            " SELECT snapshot_id FROM (SELECT snapshot_id, row_number() OVER (PARTITION BY org_id, asset_id ORDER BY created_at DESC) rn "
            " FROM audit_snapshots) r WHERE rn <= %s)", (days, keep_last))
        return cur.rowcount
