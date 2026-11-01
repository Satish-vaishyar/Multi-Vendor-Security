"""Webhook formats cef / jira / servicenow, encrypted auth header, SSRF still enforced."""
import json
import logging

import pytest
from fastapi.testclient import TestClient

from app import worker
from app.core import config as cfg
from app.core import db as dbmod
from app.main import app
from app.services import events
from app.services import webhook_formats as wf
from tests.test_webhooks import Receiver, _hook, _sql  # noqa: F401

client = TestClient(app)
TOKEN = "Bearer s3cr3t-token-VALUE-123"


@pytest.fixture()
def rx():
    r = Receiver()
    yield r
    r.close()


@pytest.fixture(autouse=True)
def _clean():
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM jobs WHERE status IN ('QUEUED','RUNNING') AND kind IN ('audit','report','webhook')")
        cur.execute("DELETE FROM webhooks")
        cur.execute("DELETE FROM webhook_deliveries")
    yield


def _env(data, event="audit.completed"):
    return {"id": "dlv_abc", "event": event, "created_at": "2026-01-01T00:00:00Z", "org_id": "ORG-X", "data": data}


# ------------------------------------------------------------------ CEF
def test_cef_escaping_blocks_field_and_event_injection():
    nasty = "evil=1 cs1=forged\nCEF:0|fake|fake|1|x|y|10|msg=pwn\\end|pipe"
    line = wf.render_cef("job.failed", _env({"job_id": "J1", "kind": "audit", "error": nasty, "asset_name": nasty}, "job.failed"),
                         events._headline("job.failed", {"job_id": "J1", "kind": "audit", "error": nasty}))
    assert "\n" not in line and "\r" not in line                       # one event, one line
    head, _, ext = line.split("|", 7)[:7], None, line.split("|", 7)[7]
    assert line.startswith("CEF:0|NSCA|Network Security Compliance Auditor|1.0|job.failed|Background job failed|6|")
    assert "\\n" in ext and "\\=" in ext and "\\\\" in ext             # newline, '=' and backslash escaped
    # every unescaped '=' must belong to a known key; the forged "cs1=forged" and "msg=pwn" became data
    import re
    keys = re.findall(r"(?:^| )([A-Za-z0-9]+)=(?:[^ ]|$)", re.sub(r"\\.", "", ext))
    assert "forged" not in keys and set(keys) <= {"rt", "externalId", "cat", "cs1Label", "cs1", "msg", "cs3Label", "cs3", "cs4Label", "cs4"}
    assert wf.cef_header("a|b\\c\nd") == "a\\|b\\\\c d"
    assert wf.cef_ext("a=b\\c\r\nd") == "a\\=b\\\\c\\nd"


def test_cef_delivery_is_plain_text_signed_and_summary_only(rx):
    h = _hook(rx.url, ("ping",), fmt="cef")
    client.post(f"/api/v1/integrations/webhooks/{h['webhook_id']}/test")
    worker.drain()
    req = rx.requests[0]
    assert req["headers"]["Content-Type"].startswith("text/plain")
    assert events.verify(h["secret"], req["headers"]["X-Timestamp"], req["body"], req["headers"]["X-Signature-256"])
    body = req["body"].decode()
    assert body.startswith("CEF:0|NSCA|") and "externalId=dlv_" in body and h["secret"] not in body


# --------------------------------------------------------- Jira / ServiceNow shape
def test_jira_and_servicenow_payload_shape_and_whitelist():
    data = {"asset_id": "AST-1", "asset_name": "edge-1", "audit_id": "AUD-1", "compliance_score": 71.5, "failed": 9,
            "changes": {"new": 2, "resolved": 1, "new_critical_high": 2}, "config_text": "enable secret 5 $1$abc", "token": "t0k"}
    e = _env(data)
    j = wf.render_jira("audit.completed", e, events._headline("audit.completed", data))
    f = j["fields"]
    assert f["project"]["key"] == cfg.WEBHOOK_JIRA_PROJECT and f["issuetype"]["name"] == cfg.WEBHOOK_JIRA_ISSUE_TYPE
    assert f["summary"].startswith("Audit completed for edge-1") and "AUD-1" in f["description"] and "nsca" in f["labels"]
    sn = wf.render_servicenow("finding.new_critical_high", _env(data, "finding.new_critical_high"),
                              events._headline("finding.new_critical_high", data))
    assert sn["urgency"] == "1" and sn["impact"] == "1" and sn["category"] == "Security" and sn["correlation_id"] == "dlv_abc"
    assert sn["short_description"] and "AST-1" in sn["description"]
    blob = json.dumps([j, sn])
    assert "enable secret" not in blob and "$1$abc" not in blob and "t0k" not in blob      # not whitelisted -> never sent


@pytest.mark.parametrize("fmt,key", [("jira", "fields"), ("servicenow", "short_description")])
def test_ticketing_delivery_carries_auth_header_but_never_exposes_it(rx, fmt, key, caplog):
    caplog.set_level(logging.DEBUG)
    r = client.post("/api/v1/integrations/webhooks", json={"name": "t", "url": rx.url, "events": ["ping"], "format": fmt,
                                                           "auth_header": f"Authorization: {TOKEN}"})
    assert r.status_code == 201, r.text
    h = r.json()["data"]
    assert h["has_auth_header"] is True and "auth_header" not in h and TOKEN not in r.text
    assert "s3cr3t" not in client.get("/api/v1/integrations/webhooks").text
    assert "s3cr3t" not in client.get(f"/api/v1/integrations/webhooks/{h['webhook_id']}").text
    stored = _sql("SELECT auth_header_enc FROM webhooks WHERE webhook_id=%s", h["webhook_id"])[0][0]
    assert stored.startswith("enc:v1:") and "s3cr3t" not in stored                          # encrypted at rest
    client.post(f"/api/v1/integrations/webhooks/{h['webhook_id']}/test")
    worker.drain()
    req = rx.requests[0]
    assert req["headers"]["Authorization"] == TOKEN and key in json.loads(req["body"])      # receiver gets it ...
    assert "s3cr3t" not in req["body"].decode()                                             # ... but not in the payload
    assert "s3cr3t" not in client.get(f"/api/v1/integrations/webhooks/{h['webhook_id']}/deliveries").text
    assert "s3cr3t" not in caplog.text and "s3cr3t" not in str(_sql("SELECT * FROM webhook_deliveries"))


def test_auth_header_validation_patch_and_clear(rx):
    base = {"name": "t", "url": rx.url, "events": ["ping"], "format": "jira"}
    for bad in ("no-colon-here", "Authorization:", "Bad Name: x", "Host: evil", "X-Signature-256: forged",
                "Authorization: a\r\nX-Injected: 1", "Authorization: a\nb"):
        assert client.post("/api/v1/integrations/webhooks", json={**base, "auth_header": bad}).status_code == 400, bad
    h = client.post("/api/v1/integrations/webhooks", json=base).json()["data"]
    assert h["has_auth_header"] is False
    p = client.patch(f"/api/v1/integrations/webhooks/{h['webhook_id']}", json={"auth_header": "X-Api-Key: k1"}).json()["data"]
    assert p["has_auth_header"] is True and "k1" not in json.dumps(p)
    p = client.patch(f"/api/v1/integrations/webhooks/{h['webhook_id']}", json={"name": "renamed"}).json()["data"]
    assert p["has_auth_header"] is True                                                     # unchanged by an unrelated patch
    p = client.patch(f"/api/v1/integrations/webhooks/{h['webhook_id']}", json={"auth_header": ""}).json()["data"]
    assert p["has_auth_header"] is False
    assert client.patch(f"/api/v1/integrations/webhooks/{h['webhook_id']}", json={"auth_header": "bogus"}).status_code == 400


def test_new_formats_still_enforce_ssrf(monkeypatch):
    monkeypatch.setattr(cfg, "WEBHOOK_ALLOW_PRIVATE", False)
    for fmt in ("cef", "jira", "servicenow"):
        for url in ("http://169.254.169.254/rest/api/2/issue", "http://10.0.0.5/api/now/table/incident", "http://127.0.0.1/x"):
            r = client.post("/api/v1/integrations/webhooks", json={"name": "x", "url": url, "events": ["ping"], "format": fmt,
                                                                   "auth_header": "Authorization: Basic abc"})
            assert r.status_code == 400, (fmt, url)
    assert "cef" in client.get("/api/v1/integrations/webhooks/catalog").json()["data"]["formats"]


def test_delivery_to_hook_that_became_unsafe_is_blocked_before_sending_credentials(rx, monkeypatch):
    r = client.post("/api/v1/integrations/webhooks", json={"name": "t", "url": rx.url, "events": ["ping"], "format": "servicenow",
                                                           "auth_header": "Authorization: Basic zzz"})
    hid = r.json()["data"]["webhook_id"]
    monkeypatch.setattr(cfg, "WEBHOOK_ALLOW_PRIVATE", False)
    client.post(f"/api/v1/integrations/webhooks/{hid}/test")
    worker.drain()
    assert rx.requests == []
