"""Dependency-free Prometheus text-format metrics (no prometheus_client).

Cardinality safety: HTTP series are labelled by method + ROUTE TEMPLATE (e.g. /api/v1/assets/{asset_id}) + status,
never by the raw path; requests that match no route collapse into "unmatched"; unknown methods into "OTHER".
Process-local counters are per API process; queue depth and worker heartbeats come from the database so they are
fleet-wide whichever process serves the scrape.
"""
from __future__ import annotations
import hmac
import logging
import threading
from typing import Dict, List, Optional, Tuple

from app.core import config as cfg
from app.core import db as dbmod
from app.core import tenancy

log = logging.getLogger("sih26155.metrics")

BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_JOB_STATUSES = ("QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED")

_lock = threading.Lock()
_requests: Dict[Tuple[str, str, str], int] = {}
_hist: Dict[Tuple[str, str], List[float]] = {}      # (method, route) -> [bucket counts..., +Inf count, sum]
_in_flight = 0


def reset() -> None:
    global _in_flight
    with _lock:
        _requests.clear()
        _hist.clear()
        _in_flight = 0


def route_template(request) -> str:
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    return path if isinstance(path, str) and path else "unmatched"


def in_flight_inc() -> None:
    global _in_flight
    with _lock:
        _in_flight += 1


def in_flight_dec() -> None:
    global _in_flight
    with _lock:
        _in_flight = max(0, _in_flight - 1)


def observe(method: str, route: str, status: int, seconds: float) -> None:
    method = method.upper() if method.upper() in _METHODS else "OTHER"
    with _lock:
        k = (method, route, str(int(status)))
        _requests[k] = _requests.get(k, 0) + 1
        h = _hist.setdefault((method, route), [0.0] * (len(BUCKETS) + 2))
        for i, b in enumerate(BUCKETS):
            if seconds <= b:
                h[i] += 1
        h[len(BUCKETS)] += 1            # +Inf / count
        h[len(BUCKETS) + 1] += seconds  # sum


def check_token(authorization: Optional[str]) -> Tuple[bool, int, str]:
    """(allowed, http_status, reason). Production without METRICS_TOKEN is refused outright."""
    tok = cfg.METRICS_TOKEN
    if cfg.ENV == "production" and not tok:
        return False, 503, "metrics disabled: METRICS_TOKEN is not configured"
    if not tok:
        return True, 200, ""
    given = ""
    if authorization and authorization[:7].lower() == "bearer ":
        given = authorization[7:].strip()
    if given and hmac.compare_digest(given.encode(), tok.encode()):
        return True, 200, ""
    return False, 401, "invalid or missing metrics token"


# --- worker heartbeat (DB-backed so any API process can report it) -------------------------------------------------

def worker_heartbeat(worker_id: str, maintenance: bool = False, retention: bool = False) -> None:
    if not dbmod.is_configured():
        return
    try:
        with dbmod.get_conn() as conn:
            cur = conn.cursor()  # type: ignore[attr-defined]
            cur.execute(
                "INSERT INTO worker_heartbeats (worker_id, last_seen, last_maintenance, last_retention) "
                "VALUES (%s, now(), CASE WHEN %s THEN now() END, CASE WHEN %s THEN now() END) "
                "ON CONFLICT (worker_id) DO UPDATE SET last_seen = now(), "
                "last_maintenance = CASE WHEN %s THEN now() ELSE worker_heartbeats.last_maintenance END, "
                "last_retention = CASE WHEN %s THEN now() ELSE worker_heartbeats.last_retention END",
                (worker_id, maintenance, retention, maintenance, retention))
            cur.execute("DELETE FROM worker_heartbeats WHERE last_seen < now() - interval '1 day'")
    except Exception as e:  # noqa: BLE001 - metrics must never break the worker
        log.debug("worker heartbeat failed: %s", e)


# --- rendering ---------------------------------------------------------------------------------------------------------

def _esc(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _lbl(**kw) -> str:
    return "{" + ",".join(f'{k}="{_esc(v)}"' for k, v in kw.items()) + "}"


def _fmt(b: float) -> str:
    return repr(float(b))


@tenancy.system
def _db_gauges() -> List[str]:
    out: List[str] = []
    if not dbmod.is_configured():
        return out
    try:
        with dbmod.get_conn() as conn:
            cur = conn.cursor()  # type: ignore[attr-defined]
            cur.execute("SELECT status, count(*) FROM jobs GROUP BY status")
            by = {s: n for s, n in cur.fetchall()}
            cur.execute("SELECT coalesce(extract(epoch FROM now() - min(created_at)), 0) FROM jobs "
                        "WHERE status = 'QUEUED' AND run_after <= now()")
            oldest = float(cur.fetchone()[0])
            cur.execute("SELECT count(*), coalesce(extract(epoch FROM now() - max(last_seen)), -1), "
                        "coalesce(extract(epoch FROM max(last_maintenance)), 0), "
                        "coalesce(extract(epoch FROM max(last_retention)), 0) FROM worker_heartbeats "
                        "WHERE last_seen > now() - interval '1 day'")
            workers, since_seen, last_maint, last_ret = cur.fetchone()
        out += ["# HELP auditor_jobs Background jobs by status.", "# TYPE auditor_jobs gauge"]
        for s in sorted(set(_JOB_STATUSES) | set(by)):
            out.append(f"auditor_jobs{_lbl(status=s)} {by.get(s, 0)}")
        out += ["# HELP auditor_job_queue_oldest_age_seconds Age of the oldest runnable QUEUED job.",
                "# TYPE auditor_job_queue_oldest_age_seconds gauge",
                f"auditor_job_queue_oldest_age_seconds {oldest:.1f}",
                "# HELP auditor_workers_seen Workers with a heartbeat in the last 24h.", "# TYPE auditor_workers_seen gauge",
                f"auditor_workers_seen {int(workers)}",
                "# HELP auditor_worker_last_heartbeat_age_seconds Seconds since the freshest worker heartbeat (-1 = never).",
                "# TYPE auditor_worker_last_heartbeat_age_seconds gauge",
                f"auditor_worker_last_heartbeat_age_seconds {float(since_seen):.1f}",
                "# HELP auditor_worker_last_maintenance_timestamp_seconds Unix time of the last worker maintenance run.",
                "# TYPE auditor_worker_last_maintenance_timestamp_seconds gauge",
                f"auditor_worker_last_maintenance_timestamp_seconds {float(last_maint):.0f}",
                "# HELP auditor_retention_last_run_timestamp_seconds Unix time of the last retention run.",
                "# TYPE auditor_retention_last_run_timestamp_seconds gauge",
                f"auditor_retention_last_run_timestamp_seconds {float(last_ret):.0f}"]
        out += ["# HELP auditor_db_up 1 if the database answered the metrics queries.", "# TYPE auditor_db_up gauge",
                "auditor_db_up 1"]
    except Exception as e:  # noqa: BLE001
        log.warning("metrics db queries failed: %s", e)
        out += ["# HELP auditor_db_up 1 if the database answered the metrics queries.", "# TYPE auditor_db_up gauge",
                "auditor_db_up 0"]
    return out


def render() -> str:
    with _lock:
        reqs = dict(_requests)
        hist = {k: list(v) for k, v in _hist.items()}
        inflight = _in_flight
    out = ["# HELP auditor_build_info Build information.", "# TYPE auditor_build_info gauge",
           f"auditor_build_info{_lbl(version=cfg.BUILD_VERSION, env=cfg.ENV)} 1",
           "# HELP auditor_http_requests_total HTTP requests by method, route template and status.",
           "# TYPE auditor_http_requests_total counter"]
    for (m, r, s), n in sorted(reqs.items()):
        out.append(f"auditor_http_requests_total{_lbl(method=m, route=r, status=s)} {n}")
    out += ["# HELP auditor_http_request_duration_seconds Request latency by method and route template.",
            "# TYPE auditor_http_request_duration_seconds histogram"]
    for (m, r), h in sorted(hist.items()):
        for i, b in enumerate(BUCKETS):
            out.append(f"auditor_http_request_duration_seconds_bucket{_lbl(method=m, route=r, le=_fmt(b))} {int(h[i])}")
        out.append(f"auditor_http_request_duration_seconds_bucket{_lbl(method=m, route=r, le='+Inf')} {int(h[len(BUCKETS)])}")
        out.append(f"auditor_http_request_duration_seconds_sum{_lbl(method=m, route=r)} {h[len(BUCKETS) + 1]:.6f}")
        out.append(f"auditor_http_request_duration_seconds_count{_lbl(method=m, route=r)} {int(h[len(BUCKETS)])}")
    out += ["# HELP auditor_http_requests_in_flight Requests currently being served by this process.",
            "# TYPE auditor_http_requests_in_flight gauge", f"auditor_http_requests_in_flight {inflight}"]
    out += _db_gauges()
    return "\n".join(out) + "\n"
