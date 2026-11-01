"""Cloud module API (docs/CLOUD_MODULE_RTM.md S04/S14). The scanner service and the store are replaced by fakes: these tests cover
the API's own rules (flag, validation, size, id format, response shaping), not the scanner or the database."""
import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import cloud
from app.core import auditlog
from app.core import security as sec

app = FastAPI()
app.include_router(cloud.router)
app.dependency_overrides[sec.require_user] = lambda: {"email": "auditor@example.com", "role": "AUDITOR"}
client = TestClient(app)
SCAN = "CSCAN-0123456789abcdef"
REPORT = {"status": "COMPLETED", "summary": {"states": {"FAIL_STATIC": 1}}, "statement": "s", "coverage": {"providers": ["aws"]},
          "findings": [], "resources": []}


class FakeResponse:
    def __init__(self, status=200, body=None, content=b"x"):
        self.status_code, self._body, self.content = status, body, content

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


@pytest.fixture(autouse=True)
def _enabled(monkeypatch):
    monkeypatch.setenv("CLOUD_MODULE_ENABLED", "true")
    monkeypatch.setattr(auditlog, "record", lambda *a, **k: None)
    monkeypatch.setattr(cloud.store, "save_report", lambda *a, **k: None)


def test_disabled_flag_hides_every_route(monkeypatch):
    monkeypatch.setenv("CLOUD_MODULE_ENABLED", "")
    assert client.get("/api/v1/cloud/scans").status_code == 404
    assert client.get("/api/v1/cloud/status").status_code == 404
    assert client.post("/api/v1/cloud/scans", files={"file": ("a.tf", b"x")}).status_code == 404
    assert client.get(f"/api/v1/cloud/scans/{SCAN}").status_code == 404
    assert client.get(f"/api/v1/cloud/scans/{SCAN}/findings").status_code == 404
    assert client.get(f"/api/v1/cloud/scans/{SCAN}/export").status_code == 404


def test_upload_is_forwarded_sanitised_and_stored(monkeypatch):
    seen = {}

    def fake_post(path, content, headers, timeout):
        seen.update(path=path, content=content, headers=headers)
        return FakeResponse(200, REPORT)
    monkeypatch.setattr(cloud, "_scanner_post", fake_post)
    r = client.post("/api/v1/cloud/scans", files={"file": ("..\\..\\evil name?.tf", b"resource")})
    assert r.status_code == 201 and r.json()["data"]["scan_id"].startswith("CSCAN-") and r.json()["data"]["status"] == "COMPLETED"
    assert seen["path"] == "/scan" and seen["content"] == b"resource" and "/" not in seen["headers"]["X-Filename"]
    assert "?" not in seen["headers"]["X-Filename"] and ".." not in seen["headers"]["X-Filename"].replace("evil", "")


def test_upload_validation_and_scanner_failures(monkeypatch):
    assert client.post("/api/v1/cloud/scans", files={"file": ("a.tf", b"")}).status_code == 400
    monkeypatch.setattr(cloud, "MAX_UPLOAD", 3)
    assert client.post("/api/v1/cloud/scans", files={"file": ("a.tf", b"abcd")}).status_code == 413
    monkeypatch.setattr(cloud, "MAX_UPLOAD", 1000)
    for status, expect in ((400, 400), (503, 502)):
        monkeypatch.setattr(cloud, "_scanner_post", lambda *a, s=status, **k: FakeResponse(s, {}))
        assert client.post("/api/v1/cloud/scans", files={"file": ("a.tf", b"x")}).status_code == expect
    monkeypatch.setattr(cloud, "_scanner_post", lambda *a, **k: FakeResponse(200, None))
    assert client.post("/api/v1/cloud/scans", files={"file": ("a.tf", b"x")}).status_code == 502

    def conflict(*a, **k):
        raise PermissionError("other org")
    monkeypatch.setattr(cloud, "_scanner_post", lambda *a, **k: FakeResponse(200, REPORT))
    monkeypatch.setattr(cloud.store, "save_report", conflict)
    assert client.post("/api/v1/cloud/scans", files={"file": ("a.tf", b"x")}).status_code == 409


def test_scanner_transport_error_is_a_502_without_details(monkeypatch):
    def boom(*a, **k):
        raise httpx.ConnectError("secret internal host")
    monkeypatch.setattr(cloud.httpx, "post", boom)
    r = client.post("/api/v1/cloud/scans", files={"file": ("a.tf", b"x")})
    assert r.status_code == 502 and "secret" not in r.text


def test_status_reports_scanner_health(monkeypatch):
    monkeypatch.setattr(cloud.httpx, "get", lambda *a, **k: FakeResponse(200, {"status": "ok"}))
    assert client.get("/api/v1/cloud/status").json()["data"]["scanner"] == {"status": "ok"}
    monkeypatch.setattr(cloud.httpx, "get", lambda *a, **k: FakeResponse(500, {}))
    assert client.get("/api/v1/cloud/status").json()["data"]["scanner"] == {"status": "error"}

    def down(*a, **k):
        raise httpx.ConnectError("x")
    monkeypatch.setattr(cloud.httpx, "get", down)
    assert client.get("/api/v1/cloud/status").json()["data"]["scanner"] == {"status": "unreachable"}


def test_read_routes_validate_ids_and_scope_to_the_store(monkeypatch):
    monkeypatch.setattr(cloud.store, "list_scans", lambda limit: [{"scan_id": SCAN}])
    assert client.get("/api/v1/cloud/scans").json()["data"]["items"] == [{"scan_id": SCAN}]
    assert client.get("/api/v1/cloud/scans?limit=500").status_code == 422
    monkeypatch.setattr(cloud.store, "get_scan", lambda sid: None)
    assert client.get(f"/api/v1/cloud/scans/{SCAN}").status_code == 404
    assert client.get("/api/v1/cloud/scans/not-an-id").status_code == 404
    assert client.get("/api/v1/cloud/scans/not-an-id/findings").status_code == 404
    assert client.get(f"/api/v1/cloud/scans/{SCAN}/findings").status_code == 404
    monkeypatch.setattr(cloud.store, "get_scan", lambda sid: {"scan_id": sid})
    monkeypatch.setattr(cloud.store, "list_findings", lambda sid, st, sev, page, size: {"items": [], "total": 0, "page": page, "size": size})
    assert client.get(f"/api/v1/cloud/scans/{SCAN}").json()["data"]["scan_id"] == SCAN
    assert client.get(f"/api/v1/cloud/scans/{SCAN}/findings?size=10").json()["data"]["size"] == 10
    assert client.get(f"/api/v1/cloud/scans/{SCAN}/findings?size=1000").status_code == 422


def test_export_formats_and_headers(monkeypatch):
    assert client.get(f"/api/v1/cloud/scans/{SCAN}/export?format=exe").status_code == 400
    monkeypatch.setattr(cloud.store, "report_for_export", lambda sid: None)
    assert client.get(f"/api/v1/cloud/scans/{SCAN}/export").status_code == 404
    monkeypatch.setattr(cloud.store, "report_for_export", lambda sid: {"findings": []})
    monkeypatch.setattr(cloud, "_scanner_post", lambda path, *a, **k: FakeResponse(200, None, b"control_id\n"))
    r = client.get(f"/api/v1/cloud/scans/{SCAN}/export?format=csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv") and r.headers["x-content-type-options"] == "nosniff"
    assert SCAN in r.headers["content-disposition"]
    monkeypatch.setattr(cloud, "_scanner_post", lambda *a, **k: FakeResponse(500, None))
    assert client.get(f"/api/v1/cloud/scans/{SCAN}/export").status_code == 502


def test_scanner_url_default_and_flag_values(monkeypatch):
    monkeypatch.delenv("CLOUD_SCANNER_URL", raising=False)
    assert cloud._scanner_url() == "http://cloud-scanner:8100"
    monkeypatch.setenv("CLOUD_SCANNER_URL", "http://x:1/")
    assert cloud._scanner_url() == "http://x:1"
    for v, want in (("TRUE", True), (" yes ", True), ("2", False), ("", False), ("disabled", False)):
        monkeypatch.setenv("CLOUD_MODULE_ENABLED", v)
        assert cloud.enabled() is want
