"""Webhooks: SSRF policy, signing, delivery through the job queue, retries, auto-disable, isolation."""
import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

from app import worker
from app.core import config as cfg
from app.core import db as dbmod
from app.core import jobs, rbac, tenancy, urlcheck, webhooks
from app.core import security as sec
from app.main import app
from app.services import events

client = TestClient(app)
CORPUS = Path(cfg.OKF_DIR) / "tests" / "corpus"
HARDENED = (CORPUS / "cisco_iosxe_core_hardened.cfg").read_text(encoding="utf-8")


class Receiver:
    """A real HTTP server that records requests and answers with scripted status codes."""

    def __init__(self):
        self.requests, self.script = [], []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                outer.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                code = outer.script.pop(0) if outer.script else 200
                self.send_response(code)
                if code in (301, 302):
                    self.send_header("Location", "http://127.0.0.1:1/elsewhere")
                self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/hook"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


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
        cur.execute("DELETE FROM webhooks")                  # hooks from earlier tests point at receivers that are gone
        cur.execute("DELETE FROM webhook_deliveries")
    yield


def _sql(q, *a):
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(q, a)
        return cur.fetchall() if cur.description else None


def _hook(url, events_=("audit.completed",), fmt="json", name="t"):
    r = client.post("/api/v1/integrations/webhooks", json={"name": name, "url": url, "events": list(events_), "format": fmt})
    assert r.status_code == 201, r.text
    return r.json()["data"]


def _run_audit(text=HARDENED):
    asset = client.post("/api/v1/assets", json={"name": f"wh-{uuid.uuid4().hex[:6]}"}).json()["data"]["asset_id"]
    cid = client.post("/api/v1/configurations/upload", data={"asset_id": asset},
                      files={"file": ("c.cfg", text.encode(), "text/plain")}).json()["data"]["configuration_id"]
    client.post("/api/v1/jobs/audit", json={"asset_id": asset, "configuration_id": cid, "run_cve": False})
    return asset


def _force_due():
    _sql("UPDATE jobs SET run_after = now() WHERE status='QUEUED'")


# ------------------------------------------------------------------------------------ SSRF
def test_ssrf_policy(monkeypatch):
    monkeypatch.setattr(cfg, "WEBHOOK_ALLOW_PRIVATE", False)
    for bad, why in [("http://127.0.0.1/x", "loopback"), ("http://localhost/x", "loopback"), ("http://[::1]/x", "loopback"),
                     ("http://169.254.169.254/latest/meta-data", "metadata"), ("http://10.1.2.3/x", "private"),
                     ("http://192.168.0.5/x", "private"), ("http://172.16.0.9/x", "private"), ("http://0.0.0.0/x", "unspecified"),
                     ("http://[::ffff:127.0.0.1]/x", "mapped loopback"), ("http://[::ffff:10.0.0.1]/x", "mapped private"),
                     ("ftp://93.184.216.34/x", "scheme"), ("file:///etc/passwd", "scheme"), ("https://user:pw@93.184.216.34/x", "creds"),
                     ("https://93.184.216.34:99999/x", "port"), ("https:///nohost", "no host"), ("not a url", "junk"),
                     ("https://definitely-not-a-real-host.invalid/x", "unresolvable")]:
        with pytest.raises(urlcheck.UnsafeURL):
            urlcheck.validate(bad)
    assert urlcheck.validate("https://93.184.216.34/hook") == ["93.184.216.34"]          # public address is fine
    monkeypatch.setattr(cfg, "WEBHOOK_ALLOW_PRIVATE", True)
    assert urlcheck.validate("https://10.1.2.3/siem")                                    # internal SIEM allowed by opt-in
    with pytest.raises(urlcheck.UnsafeURL):
        urlcheck.validate("http://169.254.169.254/x")                                    # metadata NEVER allowed
    monkeypatch.setattr(cfg, "ENV", "production")
    with pytest.raises(urlcheck.UnsafeURL):
        urlcheck.validate("http://127.0.0.1/x")                                          # loopback never allowed in production
    with pytest.raises(urlcheck.UnsafeURL):
        urlcheck.validate("http://10.1.2.3/x")                                           # plain http refused in production
    monkeypatch.setattr(cfg, "WEBHOOK_ALLOW_HTTP", True)
    assert urlcheck.validate("http://10.1.2.3/x")


def test_api_rejects_unsafe_and_invalid_definitions(monkeypatch):
    base = {"name": "x", "url": "https://93.184.216.34/h", "events": ["audit.completed"], "format": "json"}
    assert client.post("/api/v1/integrations/webhooks", json=base).status_code == 201
    monkeypatch.setattr(cfg, "WEBHOOK_ALLOW_PRIVATE", False)
    assert client.post("/api/v1/integrations/webhooks", json={**base, "url": "http://169.254.169.254/x"}).status_code == 400
    assert client.post("/api/v1/integrations/webhooks", json={**base, "url": "http://10.0.0.1/x"}).status_code == 400
    assert client.post("/api/v1/integrations/webhooks", json={**base, "events": ["nope"]}).status_code == 400
    assert client.post("/api/v1/integrations/webhooks", json={**base, "events": []}).status_code == 400
    assert client.post("/api/v1/integrations/webhooks", json={**base, "format": "xml"}).status_code == 400
    n = _sql("SELECT count(*) FROM webhooks WHERE org_id=%s", tenancy.current_org())[0][0]
    monkeypatch.setattr(cfg, "WEBHOOK_MAX_PER_ORG", n)
    assert client.post("/api/v1/integrations/webhooks", json=base).status_code == 400


# ---------------------------------------------------------------------------- secrets / signing
def test_secret_is_shown_once_stored_encrypted_and_rotatable(rx):
    h = _hook(rx.url)
    assert h["secret"].startswith("whsec_") and "secret_enc" not in h
    again = client.get(f"/api/v1/integrations/webhooks/{h['webhook_id']}").json()["data"]
    assert "secret" not in again and "secret_enc" not in again
    assert all("secret" not in x for x in client.get("/api/v1/integrations/webhooks").json()["data"]["items"])
    stored = _sql("SELECT secret_enc FROM webhooks WHERE webhook_id=%s", h["webhook_id"])[0][0]
    assert stored.startswith("enc:v1:") and h["secret"] not in stored
    new = client.post(f"/api/v1/integrations/webhooks/{h['webhook_id']}/rotate-secret").json()["data"]["secret"]
    assert new != h["secret"] and client.post("/api/v1/integrations/webhooks/WHK-NOPE/rotate-secret").status_code == 404


def test_signature_verification_rejects_tampering_replay_and_wrong_secret():
    body, ts, secret = b'{"a":1}', str(int(time.time())), "whsec_x"
    sig = events.sign(secret, ts, body)
    assert events.verify(secret, ts, body, sig)
    assert not events.verify(secret, ts, b'{"a":2}', sig)                                  # tampered body
    assert not events.verify("whsec_other", ts, body, sig)                                 # wrong secret
    old = str(int(time.time()) - 3600)
    assert not events.verify(secret, old, body, events.sign(secret, old, body))            # replay of an old delivery
    assert not events.verify(secret, "abc", body, sig) and not events.verify(secret, ts, body, "sha256=00")


# ---------------------------------------------------------------------------- end to end
def test_audit_completion_is_delivered_signed_and_without_sensitive_data(rx):
    h = _hook(rx.url, ("audit.completed", "finding.new_critical_high"))
    asset = _run_audit()
    worker.drain()                              # runs the audit, which queues the webhook ...
    worker.drain()                              # ... and this delivers it
    assert [r["headers"]["X-Event"] for r in rx.requests] == ["audit.completed"]       # no new_critical_high on a first run
    req = rx.requests[0]
    assert events.verify(h["secret"], req["headers"]["X-Timestamp"], req["body"], req["headers"]["X-Signature-256"])
    doc = json.loads(req["body"])
    assert doc["event"] == "audit.completed" and doc["org_id"] == tenancy.current_org() and doc["id"].startswith("dlv_")
    d = doc["data"]
    assert d["asset_id"] == asset and d["compliance_score"] >= 90 and d["audit_id"].startswith("AUD-")
    blob = req["body"].decode()
    assert "enable secret" not in blob and "snmp-server" not in blob and "$9$" not in blob      # no config content, no secrets
    log = client.get(f"/api/v1/integrations/webhooks/{h['webhook_id']}/deliveries").json()["data"]["items"]
    assert log[0]["status"] == "SUCCESS" and log[0]["http_status"] == 200 and log[0]["event"] == "audit.completed"
    assert client.get(f"/api/v1/integrations/webhooks/{h['webhook_id']}").json()["data"]["last_status"] == "SUCCESS"


def test_regression_triggers_new_critical_high_event_and_event_filtering(rx):
    rx_all, rx_crit = rx, Receiver()
    try:
        _hook(rx_all.url, ("audit.completed",), name="all")
        _hook(rx_crit.url, ("finding.new_critical_high",), name="crit")
        asset = client.post("/api/v1/assets", json={"name": f"reg-{uuid.uuid4().hex[:6]}"}).json()["data"]["asset_id"]

        def audit(text):
            cid = client.post("/api/v1/configurations/upload", data={"asset_id": asset},
                              files={"file": ("c.cfg", text.encode(), "text/plain")}).json()["data"]["configuration_id"]
            client.post("/api/v1/jobs/audit", json={"asset_id": asset, "configuration_id": cid, "run_cve": False})
            worker.drain()
            worker.drain()

        audit(HARDENED)
        assert len(rx_all.requests) == 1 and rx_crit.requests == []
        audit(HARDENED.replace(" transport input ssh", " transport input all"))              # telnet appears
        assert len(rx_all.requests) == 2
        crit = json.loads(rx_crit.requests[0]["body"])
        assert crit["event"] == "finding.new_critical_high" and crit["data"]["changes"]["new_critical_high"] >= 1
    finally:
        rx_crit.close()


@pytest.mark.parametrize("fmt,key", [("slack", "text"), ("teams", "summary")])
def test_chat_formats(rx, fmt, key):
    h = _hook(rx.url, ("ping",), fmt=fmt)
    client.post(f"/api/v1/integrations/webhooks/{h['webhook_id']}/test")
    worker.drain()
    doc = json.loads(rx.requests[0]["body"])
    assert key in doc and "Webhook test" in doc[key] and "secret" not in json.dumps(doc)


# ------------------------------------------------------------------------ retries / failures
def test_5xx_is_retried_then_succeeds_and_both_attempts_are_logged(rx):
    rx.script = [500, 200]
    h = _hook(rx.url, ("ping",))
    jid = jobs.enqueue("webhook", {"webhook_id": h["webhook_id"], "event": "ping", "data": {}}, max_attempts=5)
    worker.drain()
    first = jobs.get(jid)
    assert first["status"] == jobs.QUEUED and first["attempts"] == 1                       # 500 -> retry scheduled with backoff
    assert first["run_after"] > time.time() + 3
    _force_due()
    worker.drain()
    assert jobs.get(jid)["status"] == jobs.COMPLETED and len(rx.requests) == 2
    log = client.get(f"/api/v1/integrations/webhooks/{h['webhook_id']}/deliveries").json()["data"]["items"]
    assert sorted(x["status"] for x in log) == ["FAILED", "SUCCESS"]
    assert {x["http_status"] for x in log} == {500, 200}
    assert client.get(f"/api/v1/integrations/webhooks/{h['webhook_id']}").json()["data"]["consecutive_failures"] == 0   # success resets


def test_4xx_is_permanent_but_429_is_retried(rx):
    h = _hook(rx.url, ("ping",))
    rx.script = [400]
    j1 = jobs.enqueue("webhook", {"webhook_id": h["webhook_id"], "event": "ping", "data": {}}, max_attempts=5)
    worker.drain()
    assert jobs.get(j1)["status"] == jobs.FAILED and jobs.get(j1)["attempts"] == 1 and "HTTP 400" in jobs.get(j1)["error"]
    rx.script = [429]
    j2 = jobs.enqueue("webhook", {"webhook_id": h["webhook_id"], "event": "ping", "data": {}}, max_attempts=5)
    worker.drain()
    assert jobs.get(j2)["status"] == jobs.QUEUED                                           # rate limited -> try again later


def test_redirects_are_not_followed(rx):
    h = _hook(rx.url, ("ping",))
    rx.script = [302]
    jid = jobs.enqueue("webhook", {"webhook_id": h["webhook_id"], "event": "ping", "data": {}}, max_attempts=1)
    worker.drain()
    assert jobs.get(jid)["status"] == jobs.FAILED and len(rx.requests) == 1                # a redirect cannot bounce us elsewhere


def test_unreachable_receiver_fails_gracefully_and_auto_disables(rx, monkeypatch):
    monkeypatch.setattr(cfg, "WEBHOOK_DISABLE_AFTER", 2)
    h = _hook(rx.url, ("ping",))
    rx.close()
    for _ in range(2):
        jid = jobs.enqueue("webhook", {"webhook_id": h["webhook_id"], "event": "ping", "data": {}}, max_attempts=1)
        worker.drain()
        assert jobs.get(jid)["status"] == jobs.FAILED
    hook = client.get(f"/api/v1/integrations/webhooks/{h['webhook_id']}").json()["data"]
    assert hook["enabled"] is False and "repeated delivery failures" in hook["disabled_reason"] and hook["consecutive_failures"] == 2
    assert webhooks.matching("ping") == [] or h["webhook_id"] not in {x["webhook_id"] for x in webhooks.matching("ping")}
    again = client.patch(f"/api/v1/integrations/webhooks/{h['webhook_id']}", json={"enabled": True}).json()["data"]
    assert again["enabled"] is True and again["consecutive_failures"] == 0 and again["disabled_reason"] is None


def test_delivery_to_a_hook_that_became_unsafe_or_was_deleted_is_refused(rx, monkeypatch):
    h = _hook(rx.url, ("ping",))
    monkeypatch.setattr(cfg, "WEBHOOK_ALLOW_PRIVATE", False)                              # policy tightened after the hook was saved
    jid = jobs.enqueue("webhook", {"webhook_id": h["webhook_id"], "event": "ping", "data": {}})
    worker.drain()
    assert jobs.get(jid)["status"] == jobs.FAILED and "blocked" in jobs.get(jid)["error"] and rx.requests == []
    monkeypatch.setattr(cfg, "WEBHOOK_ALLOW_PRIVATE", True)
    client.delete(f"/api/v1/integrations/webhooks/{h['webhook_id']}")
    jid2 = jobs.enqueue("webhook", {"webhook_id": h["webhook_id"], "event": "ping", "data": {}})
    worker.drain()
    assert jobs.get(jid2)["status"] == jobs.FAILED and "deleted" in jobs.get(jid2)["error"]


def test_job_failed_event_and_no_feedback_loop(rx):
    h = _hook(rx.url, ("job.failed",))
    cid_missing = jobs.enqueue("audit", {"configuration_id": "CFG-GONE", "asset_id": "AST-GONE"})
    worker.drain()                                           # the audit fails permanently -> job.failed queued
    assert jobs.get(cid_missing)["status"] == jobs.FAILED
    rx.script = [400]                                        # the receiver rejects it -> the WEBHOOK job fails
    worker.drain()
    assert len(rx.requests) == 1 and json.loads(rx.requests[0]["body"])["data"]["job_id"] == cid_missing
    assert worker.drain() == 0                               # a failing webhook delivery does not create further events
    assert _sql("SELECT count(*) FROM jobs WHERE kind='webhook' AND payload->>'event'='job.failed' AND payload->'data'->>'kind'='webhook'")[0][0] == 0


def test_update_validation_and_listing(rx):
    h = _hook(rx.url, ("ping",))
    hid = h["webhook_id"]
    assert client.patch(f"/api/v1/integrations/webhooks/{hid}", json={"events": ["bogus"]}).status_code == 400
    assert client.patch(f"/api/v1/integrations/webhooks/{hid}", json={"url": "ftp://example.com/hook"}).status_code == 400
    p = client.patch(f"/api/v1/integrations/webhooks/{hid}", json={"name": "renamed", "events": ["audit.completed", "ping"], "format": "slack"}).json()["data"]
    assert p["name"] == "renamed" and p["format"] == "slack" and p["events"] == ["audit.completed", "ping"]
    assert client.patch("/api/v1/integrations/webhooks/WHK-NOPE", json={"name": "x"}).status_code == 404
    assert client.get("/api/v1/integrations/webhooks/WHK-NOPE").status_code == 404
    assert client.get("/api/v1/integrations/webhooks/WHK-NOPE/deliveries").status_code == 404
    assert client.post("/api/v1/integrations/webhooks/WHK-NOPE/test").status_code == 404
    assert client.get("/api/v1/integrations/webhooks/catalog").json()["data"]["events"][0] == "audit.completed"
    assert client.delete(f"/api/v1/integrations/webhooks/{hid}").status_code == 200
    assert client.delete(f"/api/v1/integrations/webhooks/{hid}").status_code == 404


# -------------------------------------------------------------------- tenancy + RBAC
def test_webhooks_are_tenant_isolated_and_admin_only(rx, monkeypatch):
    monkeypatch.setattr(cfg, "REQUIRE_AUTH", True)
    sec.reset_throttle()
    for org in ("ORG-W1", "ORG-W2"):
        _sql("INSERT INTO organizations (org_id,name) VALUES (%s,%s) ON CONFLICT DO NOTHING", org, org)

    def hdr(role, org):
        email = f"{role.lower()}-{uuid.uuid4().hex[:6]}@example.com"
        sec.create_user(email, role, "Str0ng!Passw0rd#1", role, org_id=org)
        t = client.post("/api/v1/auth/login", json={"email": email, "password": "Str0ng!Passw0rd#1"}).json()["data"]["access_token"]
        return {"Authorization": f"Bearer {t}"}

    a1, a2, auditor = hdr(rbac.ADMIN, "ORG-W1"), hdr(rbac.ADMIN, "ORG-W2"), hdr(rbac.AUDITOR, "ORG-W1")
    body = {"name": "x", "url": rx.url, "events": ["ping"]}
    assert client.post("/api/v1/integrations/webhooks", headers=auditor, json=body).status_code == 403
    assert client.get("/api/v1/integrations/webhooks", headers=auditor).status_code == 403
    hid = client.post("/api/v1/integrations/webhooks", headers=a1, json=body).json()["data"]["webhook_id"]
    assert client.get(f"/api/v1/integrations/webhooks/{hid}", headers=a2).status_code == 404
    assert client.delete(f"/api/v1/integrations/webhooks/{hid}", headers=a2).status_code == 404
    assert client.post(f"/api/v1/integrations/webhooks/{hid}/test", headers=a2).status_code == 404
    assert client.get("/api/v1/integrations/webhooks", headers=a2).json()["data"]["items"] == []
    with tenancy.use_org("ORG-W2"):
        assert events.emit("ping", {}) == 0                       # org 2 has no subscribers; org 1's hook is untouched
    with tenancy.use_org("ORG-W1"):
        assert events.emit("ping", {}) == 1
