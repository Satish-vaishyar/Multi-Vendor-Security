from fastapi.testclient import TestClient

from cloud import __version__
from cloud.service import app

client = TestClient(app)


def test_healthz_reports_flag_state(monkeypatch):
    monkeypatch.delenv("CLOUD_MODULE_ENABLED", raising=False)
    body = client.get("/healthz").json()
    assert body == {"status": "ok", "version": __version__, "module_enabled": False}
    monkeypatch.setenv("CLOUD_MODULE_ENABLED", "true")
    assert client.get("/healthz").json()["module_enabled"] is True


def test_no_interactive_docs_exposed():
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_export_endpoint_renders_formats_and_rejects_bad_input(monkeypatch):
    rep = {"findings": [{"control_id": "C", "title": "t", "severity": "HIGH", "evidence_state": "FAIL_STATIC", "source": {"file": "m.tf", "line_start": 2}}]}
    monkeypatch.delenv("CLOUD_MODULE_ENABLED", raising=False)
    assert client.post("/export/json", json=rep).status_code == 503
    monkeypatch.setenv("CLOUD_MODULE_ENABLED", "true")
    assert client.post("/export/exe", json=rep).status_code == 404
    assert client.post("/export/csv", json=rep).text.startswith("control_id,")
    assert '"version": "2.1.0"' in client.post("/export/sarif", json=rep).text
    assert client.post("/export/json", json=rep).json()["findings"][0]["control_id"] == "C"
    assert client.post("/export/json", content=b"{").status_code == 400
    assert client.post("/export/json", content=b"[1]").status_code == 400
    monkeypatch.setattr("cloud.service.MAX_EXPORT_BODY", 5)
    assert client.post("/export/json", json=rep).status_code == 413
