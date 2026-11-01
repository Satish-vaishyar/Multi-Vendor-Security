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
