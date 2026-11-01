"""Branch coverage for the remaining core modules: collector transport failures, OIDC transport + validation,
logging, metrics, limits, persistence helpers, config guards and MFA edge cases."""
import asyncio
import io
import logging
import runpy
import socket
import types
import uuid

import pytest

from app.core import auditlog, collector, keyprovider, limits, logsetup, metrics, mfa, oidc, persist, tenancy
from app.core import config as cfg
from app.core import db as dbmod

paramiko = pytest.importorskip("paramiko")


# ---------------------------------------------------------------- collector: transport edge cases
def test_unresolvable_host_with_no_addresses(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [])
    with pytest.raises(collector.CollectError, match="does not resolve"):
        collector.check_target("empty.example", 22)


def test_ssh_negotiation_failure_is_a_clean_error(monkeypatch):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    monkeypatch.setattr(paramiko.Transport, "start_client", lambda self, **k: (_ for _ in ()).throw(paramiko.SSHException("bad banner")))
    try:
        with pytest.raises(collector.CollectError, match="negotiation failed"):
            collector.ParamikoTransport("127.0.0.1", srv.getsockname()[1], 2.0)
    finally:
        srv.close()


def _bare_transport(**attrs):
    t = object.__new__(collector.ParamikoTransport)
    t._p = paramiko
    t._t = types.SimpleNamespace(**attrs)
    return t


def test_key_authentication_uses_the_first_key_type_that_parses():
    pem = io.StringIO()
    paramiko.RSAKey.generate(2048).write_private_key(pem)
    used = []
    t = _bare_transport(auth_publickey=lambda user, key: used.append((user, type(key).__name__)))
    t.login("netops", pem.getvalue(), "key")
    assert used == [("netops", "RSAKey")]


def test_command_channel_failures():
    def refused(timeout=None):
        raise paramiko.SSHException("channel refused")
    with pytest.raises(collector.CollectError, match="refused the command channel"):
        _bare_transport(open_session=refused).run("show version", 100, 1.0)

    class Chan:
        def __init__(self, exc):
            self.exc, self.closed = exc, False

        def settimeout(self, t):
            pass

        def exec_command(self, c):
            pass

        def recv(self, n):
            raise self.exc

        def close(self):
            self.closed = True
    with pytest.raises(collector.CollectError, match="timed out"):
        _bare_transport(open_session=lambda timeout=None: Chan(socket.timeout())).run("show version", 100, 1.0)
    # the device closing the channel abruptly ends the read: what arrived so far is returned
    assert _bare_transport(open_session=lambda timeout=None: Chan(paramiko.SSHException("closed"))).run("show version", 100, 1.0) == ""


def test_closing_a_dead_transport_never_raises():
    t = _bare_transport(close=lambda: (_ for _ in ()).throw(OSError("already closed")))
    t.close()


# ---------------------------------------------------------------- OIDC transport + validation
def test_oidc_http_transport_maps_status_codes(monkeypatch):
    class R:
        def __init__(self, code):
            self.status_code = code

        def json(self):
            return {"ok": 1}
    monkeypatch.setattr(oidc.httpx, "get", lambda *a, **k: R(200))
    monkeypatch.setattr(oidc.httpx, "post", lambda *a, **k: R(200))
    assert oidc._get("https://idp/x") == {"ok": 1} and oidc._post_form("https://idp/t", {"a": "b"}) == {"ok": 1}
    monkeypatch.setattr(oidc.httpx, "get", lambda *a, **k: R(503))
    monkeypatch.setattr(oidc.httpx, "post", lambda *a, **k: R(400))
    with pytest.raises(oidc.SSOError, match="idp_unreachable"):
        oidc._get("https://idp/x")
    with pytest.raises(oidc.SSOError, match="token_exchange_failed"):
        oidc._post_form("https://idp/t", {})


@pytest.fixture
def idp_cfg(monkeypatch):
    for k, v in (("OIDC_ISSUER", "https://idp.example.com/r"), ("OIDC_CLIENT_ID", "cid"), ("OIDC_CLIENT_SECRET", "s" * 20),
                 ("OIDC_REDIRECT_URI", "https://api.example.com/cb")):
        monkeypatch.setattr(cfg, k, v)
    oidc.reset_cache()
    yield
    oidc.reset_cache()


def test_discovery_refuses_plain_http_endpoints_outside_development(monkeypatch, idp_cfg):
    doc = {"issuer": "https://idp.example.com/r", "authorization_endpoint": "http://idp/auth",
           "token_endpoint": "https://idp/token", "jwks_uri": "https://idp/certs"}
    monkeypatch.setattr(oidc, "_get", lambda url: doc)
    assert oidc.discovery()["authorization_endpoint"].startswith("http://")        # development tolerates it
    oidc.reset_cache()
    monkeypatch.setattr(cfg, "ENV", "production")
    with pytest.raises(oidc.SSOError, match="insecure_endpoint"):
        oidc.discovery()


def test_a_token_response_without_an_id_token_is_refused(monkeypatch, idp_cfg):
    doc = {"issuer": "https://idp.example.com/r", "authorization_endpoint": "https://idp/auth",
           "token_endpoint": "https://idp/token", "jwks_uri": "https://idp/certs"}
    monkeypatch.setattr(oidc, "_get", lambda url: doc)
    url, tx = oidc.begin()
    state = dict(p.split("=", 1) for p in url.split("?", 1)[1].split("&"))["state"]
    monkeypatch.setattr(oidc, "_post_form", lambda url, data: {"access_token": "x"})
    with pytest.raises(oidc.SSOError, match="no_id_token"):
        oidc.complete("code", state, tx)


# ---------------------------------------------------------------- logging
def test_logging_helpers_never_break_on_redaction_or_tenancy_errors(monkeypatch):
    import app.core.redact as redact
    monkeypatch.setattr(redact, "redact_secrets", lambda t: (_ for _ in ()).throw(RuntimeError("rules unavailable")))
    assert "[REDACTED]" in logsetup.scrub("password=hunter2")
    rec = logging.LogRecord("x", logging.INFO, __file__, 1, "msg %s", (1, 2), None)         # formatting args mismatch -> exception
    assert logsetup.RedactFilter().filter(rec) is True
    monkeypatch.setattr(tenancy, "_org", None)                                           # tenancy lookup fails -> org is simply absent
    out = logsetup.JsonFormatter().format(logging.LogRecord("x", logging.INFO, __file__, 1, "hello", (), None))
    assert '"org_id": null' in out


# ---------------------------------------------------------------- metrics / audit log without a database
def test_metrics_and_audit_log_are_noops_without_a_database(monkeypatch):
    monkeypatch.setattr(dbmod, "is_configured", lambda: False)
    metrics.worker_heartbeat("w1")
    assert metrics._db_gauges() == []
    auditlog.record("x.y")


def test_worker_heartbeat_swallows_database_errors(monkeypatch):
    monkeypatch.setattr(dbmod, "get_conn", lambda: (_ for _ in ()).throw(RuntimeError("db down")))
    metrics.worker_heartbeat("w1", maintenance=True)


# ---------------------------------------------------------------- limits
def test_an_app_that_swallows_the_abort_still_gets_a_413():
    sent = []

    async def inner(scope, receive, send):
        try:
            await receive()
        except BaseException:           # noqa: BLE001 - a framework that eats the abort and answers nothing
            return

    async def send(msg):
        sent.append(msg)
    big = b"x" * (cfg.MAX_JSON_BODY_BYTES + 10)

    async def receive():
        return {"type": "http.request", "body": big, "more_body": False}
    asyncio.run(limits.BodyLimitMiddleware(inner)({"type": "http", "path": "/", "headers": [], "query_string": b""}, receive, send))
    assert sent and sent[0]["status"] == 413


def test_rate_limit_buckets_are_bounded(monkeypatch):
    limits.reset()
    monkeypatch.setattr(limits, "_MAX_KEYS", 3)
    for i in range(3):
        limits._take(f"k{i}", 1, 60, 5, 0.0)
    assert limits._take("fresh", 1, 60, 5, 10_000.0) == 0.0          # idle buckets were evicted to make room
    assert set(limits._buckets) == {"fresh"}
    limits.reset()


# ---------------------------------------------------------------- persistence helpers
def _org():
    o = "ORG-COV2-" + uuid.uuid4().hex[:6].upper()
    with dbmod.get_conn() as conn:
        conn.cursor().execute("INSERT INTO organizations (org_id, name) VALUES (%s, %s)", (o, o))
    return o


def test_persist_passes_plain_values_through_and_clears_only_the_callers_org():
    assert persist._adapt("assets", "name", "x") == "x" and persist._adapt("assets", "name", None) is None
    org = _org()
    with tenancy.use_org(org):
        persist.save("assets", {"asset_id": "AST-" + uuid.uuid4().hex[:8], "name": "to-clear"})
        assert persist.clear("assets") == 1
        assert persist.find("assets") == []


def test_encrypted_entities_are_decrypted_by_projected_reads():
    org = _org()
    with tenancy.use_org(org):
        aid = "AST-" + uuid.uuid4().hex[:8]
        persist.save("assets", {"asset_id": aid, "name": "a"})
        cid = "CFG-" + uuid.uuid4().hex[:8]
        persist.save("configurations", {"configuration_id": cid, "asset_id": aid, "config_text": "snmp-server community SECRET RO\n", "filename": "x"})
        assert persist.select("configurations", ["configuration_id", "config_text"])[0]["config_text"].startswith("snmp-server")
        rows, total = persist.select_page("configurations", ["configuration_id", "config_text"])
        assert total == 1 and rows[0]["config_text"].startswith("snmp-server")


# ---------------------------------------------------------------- config guards (executed in a fresh namespace)
def test_environment_typos_and_unsafe_production_configs_fail_closed(monkeypatch):
    monkeypatch.setenv("ENV", "prod")
    with pytest.raises(RuntimeError, match="ENV must be"):
        runpy.run_path(cfg.__file__)
    monkeypatch.setenv("ENV", "production")
    monkeypatch.setenv("JWT_SECRET", "short")
    with pytest.raises(RuntimeError, match="Unsafe production configuration"):
        runpy.run_path(cfg.__file__)


# ---------------------------------------------------------------- key provider / MFA edges
def test_aws_provider_needs_region_and_key_id(monkeypatch):
    monkeypatch.setattr(cfg, "KEY_PROVIDER", "aws-kms")
    monkeypatch.setattr(cfg, "AWS_REGION", "")
    with pytest.raises(keyprovider.KeyProviderError, match="AWS_REGION"):
        keyprovider._aws("Encrypt", {})


def test_mfa_for_users_without_enrolment():
    assert mfa.confirm_enrolment("USR-DOES-NOT-EXIST", "123456") is None
    assert mfa.check("USR-DOES-NOT-EXIST", "123456") is False
