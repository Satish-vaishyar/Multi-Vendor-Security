"""Prometheus /metrics (hand-rolled), its auth, label-cardinality safety and JSON structured logging."""
import io
import json
import logging
import re

import pytest
from fastapi.testclient import TestClient

from app.core import config as cfg
from app.core import logsetup, metrics
from app.main import app

client = TestClient(app)
TOKEN = "t" * 24


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.setattr(cfg, "REQUIRE_AUTH", False)
    monkeypatch.setattr(cfg, "METRICS_TOKEN", "")
    metrics.reset()
    yield
    metrics.reset()


def test_metrics_open_in_dev_without_token():
    r = client.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    body = r.text
    assert 'auditor_build_info{version="' in body
    assert "# TYPE auditor_http_request_duration_seconds histogram" in body
    assert "auditor_http_requests_in_flight" in body
    for st in ("QUEUED", "RUNNING", "FAILED"):
        assert f'auditor_jobs{{status="{st}"}}' in body
    assert "auditor_job_queue_oldest_age_seconds" in body and "auditor_db_up 1" in body


def test_metrics_requires_bearer_when_token_set(monkeypatch):
    monkeypatch.setattr(cfg, "METRICS_TOKEN", TOKEN)
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/metrics", headers={"Authorization": TOKEN}).status_code == 401        # scheme required
    r = client.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200 and "auditor_build_info" in r.text


def test_metrics_refused_in_production_without_token(monkeypatch):
    monkeypatch.setattr(cfg, "ENV", "production")
    r = client.get("/metrics")
    assert r.status_code == 503 and "METRICS_TOKEN" in r.text
    assert client.get("/metrics", headers={"Authorization": "Bearer anything"}).status_code == 503
    monkeypatch.setattr(cfg, "METRICS_TOKEN", TOKEN)
    assert client.get("/metrics", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200
    assert client.get("/metrics").status_code == 401
    monkeypatch.setattr(cfg, "METRICS_TOKEN", "")
    assert any("METRICS_TOKEN" in w for w in cfg.production_warnings())
    monkeypatch.setattr(cfg, "ENV", "development")
    assert cfg.production_warnings() == []


def test_labels_use_route_templates_not_raw_paths():
    client.get("/api/v1/assets/AST-secret-id-12345")
    client.get("/api/v1/assets/AST-another-67890")
    client.get("/no/such/path/with/id/987654")
    client.request("BREW", "/health")
    text = client.get("/metrics").text
    assert 'route="/api/v1/assets/{asset_id}"' in text
    assert "AST-secret-id-12345" not in text and "AST-another-67890" not in text
    assert "987654" not in text and 'route="unmatched"' in text
    assert 'method="OTHER"' in text and "BREW" not in text
    series = re.findall(r'auditor_http_requests_total\{method="GET",route="/api/v1/assets/\{asset_id\}",status="(\d+)"\} (\d+)', text)
    assert sum(int(n) for _, n in series) == 2          # two different ids collapse into one series


def test_histogram_is_cumulative_and_consistent():
    metrics.observe("GET", "/x/{id}", 200, 0.004)
    metrics.observe("GET", "/x/{id}", 200, 0.3)
    metrics.observe("GET", "/x/{id}", 500, 99)
    text = metrics.render()
    b = {m.group(1): int(m.group(2)) for m in re.finditer(
        r'duration_seconds_bucket\{method="GET",route="/x/\{id\}",le="([^"]+)"\} (\d+)', text)}
    assert b["0.005"] == 1 and b["0.25"] == 1 and b["0.5"] == 2 and b["+Inf"] == 3
    vals = [b[k] for k in b]
    assert vals == sorted(vals)
    assert 'duration_seconds_count{method="GET",route="/x/{id}"} 3' in text
    assert 'requests_total{method="GET",route="/x/{id}",status="500"} 1' in text


def test_in_flight_never_negative():
    metrics.in_flight_dec()
    metrics.in_flight_inc()
    assert "auditor_http_requests_in_flight 1" in metrics.render()


def test_worker_heartbeat_and_queue_depth_exposed():
    metrics.worker_heartbeat("w-test-1", maintenance=True, retention=True)
    text = metrics.render()
    m = re.search(r"auditor_worker_last_heartbeat_age_seconds (-?[\d.]+)", text)
    assert m and 0 <= float(m.group(1)) < 60
    assert float(re.search(r"auditor_worker_last_maintenance_timestamp_seconds (\d+)", text).group(1)) > 1e9
    assert float(re.search(r"auditor_retention_last_run_timestamp_seconds (\d+)", text).group(1)) > 1e9
    assert int(re.search(r"auditor_workers_seen (\d+)", text).group(1)) >= 1


def test_db_failure_reports_db_up_zero(monkeypatch):
    from app.core import db as dbmod

    def boom():
        raise RuntimeError("down")
    monkeypatch.setattr(dbmod, "get_conn", boom)
    assert "auditor_db_up 0" in metrics.render()


# --- structured logging -----------------------------------------------------------------------------------------------

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.abcdefghijklmnop"


def _capture(fmt):
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    h.addFilter(logsetup.RedactFilter())
    h.setFormatter(logsetup.JsonFormatter() if fmt == "json" else logging.Formatter("%(message)s"))
    lg = logging.getLogger("sih26155.test")
    lg.setLevel(logging.INFO)
    lg.addHandler(h)
    return lg, h, buf


def test_json_log_has_context_and_no_secrets():
    lg, h, buf = _capture("json")
    try:
        tok = logsetup.request_id_var.set("req-abc123")
        lg.info("login password=hunter2secret token: abc123xyz Authorization: Bearer %s", JWT,
                extra={"org_id": "ORG-DEFAULT"})
        try:
            raise ValueError("bad api_key=SUPERSECRETKEY1 here")
        except ValueError:
            lg.exception("boom")
        logsetup.request_id_var.reset(tok)
    finally:
        lg.removeHandler(h)
    lines = [json.loads(x) for x in buf.getvalue().splitlines()]
    assert len(lines) == 2
    first = lines[0]
    assert first["request_id"] == "req-abc123" and first["org_id"] == "ORG-DEFAULT"
    assert first["level"] == "INFO" and first["logger"] == "sih26155.test" and first["ts"].endswith("+00:00")
    raw = buf.getvalue()
    for secret in ("hunter2secret", "abc123xyz", JWT, "SUPERSECRETKEY1"):
        assert secret not in raw
    assert "[REDACTED]" in first["msg"] and "exc" in lines[1]


def test_text_format_is_also_redacted():
    lg, h, buf = _capture("text")
    try:
        lg.info("password=hunter2secret Bearer %s", JWT)
    finally:
        lg.removeHandler(h)
    assert "hunter2secret" not in buf.getvalue() and JWT not in buf.getvalue()


def test_request_log_line_in_json_mode_carries_request_id(monkeypatch):
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    h.addFilter(logsetup.RedactFilter())
    h.setFormatter(logsetup.JsonFormatter())
    root = logging.getLogger()
    root.addHandler(h)
    try:
        client.get("/health", headers={"X-Request-ID": "rid-json-1"})
    finally:
        root.removeHandler(h)
    recs = [json.loads(x) for x in buf.getvalue().splitlines() if x.startswith("{")]
    mine = [r for r in recs if r["request_id"] == "rid-json-1"]
    assert mine and "/health" in mine[0]["msg"] and "org_id" in mine[0]


def test_configure_installs_single_handler_and_is_idempotent():
    root = logging.getLogger()
    before = list(root.handlers)
    try:
        logsetup.configure("json")
        logsetup.configure("json")
        mine = [x for x in root.handlers if getattr(x, "_auditor", False)]
        assert len(mine) == 1 and isinstance(mine[0].formatter, logsetup.JsonFormatter)
        logsetup.configure("text")
        mine = [x for x in root.handlers if getattr(x, "_auditor", False)]
        assert len(mine) == 1 and not isinstance(mine[0].formatter, logsetup.JsonFormatter)
    finally:
        for x in list(root.handlers):
            if x not in before:
                root.removeHandler(x)
        for x in before:
            if x not in root.handlers:
                root.addHandler(x)
