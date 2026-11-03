"""Live collection: read-only allow-list, host-key pinning before auth, credential vault, RBAC, job handler.
The protocol-level tests drive a REAL in-process SSH server through paramiko."""
import socket
import threading
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core import collector, rbac
from app.core import config as cfg
from app.core import db as dbmod
from app.core import security as sec
from app.main import app
from app.services import collection, job_handlers

client = TestClient(app)
PW = "Str0ng!Passw0rd#1"
CONFIG = ("hostname lab-r1\nservice password-encryption\nenable secret 9 $9$abc\nline vty 0 4\n transport input telnet\n"
          "snmp-server community public RO\n")


# ---------------------------------------------------------------- fakes
class FakeTransport:
    def __init__(self, key=b"host-key-blob", outputs=None, fail_login=False):
        self.key, self.outputs, self.fail_login = key, outputs or {}, fail_login
        self.log, self.closed = [], False

    def host_key(self):
        self.log.append("host_key")
        return self.key

    def login(self, username, secret, auth_type):
        self.log.append(("login", username, auth_type))
        if self.fail_login:
            raise collector.CollectError("authentication failed")

    def run(self, command, max_bytes, timeout):
        self.log.append(("run", command))
        return self.outputs.get(command, "")

    def close(self):
        self.closed = True


def _factory(t):
    return lambda addr, port, timeout: t


@pytest.fixture(autouse=True)
def _dev_collect(monkeypatch):
    monkeypatch.setattr(cfg, "COLLECT_ALLOW_LOOPBACK", True)
    monkeypatch.setattr(cfg, "COLLECT_ALLOWED_CIDRS", [])
    monkeypatch.setattr(cfg, "COLLECT_ALLOW_PRIVATE", True)


# ---------------------------------------------------------------- allow-list & targets
def test_only_allow_listed_read_only_commands_can_be_sent():
    collector.assert_read_only("cisco_ios", "show running-config")
    for bad in ("configure terminal", "show running-config; reload", "write memory", "show running-config | include x",
                "copy running-config tftp:", "", "show   running-config", "SHOW RUNNING-CONFIG"):
        with pytest.raises(collector.CollectError):
            collector.assert_read_only("cisco_ios", bad)
    with pytest.raises(collector.CollectError):
        collector.assert_read_only("nope", "show running-config")
    for p in collector.PROFILES.values():             # every profile command is a read: it starts with show / get
        for c in p.commands:
            assert c.split()[0] in ("show", "get"), c
            assert not any(w in c.lower().replace("|", " ").split() for w in ("configure", "conf", "write", "reload", "delete",
                                                                             "erase", "copy", "clear", "debug", "commit", "shutdown"))


@pytest.mark.parametrize("host", ["169.254.169.254", "169.254.1.1", "224.0.0.1", "0.0.0.0", "100.100.100.200", "fd00:ec2::254"])
def test_dangerous_targets_are_refused(host):
    with pytest.raises(collector.CollectError):
        collector.check_target(host, 22)


def test_loopback_private_cidr_and_bad_input_rules(monkeypatch):
    assert collector.check_target("127.0.0.1", 22) == "127.0.0.1"
    monkeypatch.setattr(cfg, "COLLECT_ALLOW_LOOPBACK", False)
    with pytest.raises(collector.CollectError):
        collector.check_target("127.0.0.1", 22)
    monkeypatch.setattr(cfg, "ENV", "production")
    monkeypatch.setattr(cfg, "COLLECT_ALLOW_LOOPBACK", True)          # never honoured in production
    with pytest.raises(collector.CollectError):
        collector.check_target("127.0.0.1", 22)
    monkeypatch.setattr(cfg, "ENV", "development")
    assert collector.check_target("10.1.2.3", 22) == "10.1.2.3"
    monkeypatch.setattr(cfg, "COLLECT_ALLOW_PRIVATE", False)
    with pytest.raises(collector.CollectError):
        collector.check_target("10.1.2.3", 22)
    monkeypatch.setattr(cfg, "COLLECT_ALLOWED_CIDRS", ["10.1.0.0/16"])
    assert collector.check_target("10.1.2.3", 22) == "10.1.2.3"
    with pytest.raises(collector.CollectError):
        collector.check_target("10.9.9.9", 22)
    for host, port in (("", 22), ("a b", 22), ("h/x", 22), ("x" * 300, 22), ("10.1.2.3", 0), ("10.1.2.3", 70000),
                       ("nonexistent.invalid", 22)):
        with pytest.raises(collector.CollectError):
            collector.check_target(host, port)


def test_fingerprint_format_and_comparison():
    fp = collector.fingerprint(b"abc")
    assert fp.startswith("SHA256:") and "=" not in fp
    assert collector.same_fingerprint(fp, " " + fp + " ") and not collector.same_fingerprint(fp, fp[:-1] + "A")


# ---------------------------------------------------------------- orchestration (fake transport)
def _run(t, **kw):
    args = dict(host="127.0.0.1", port=22, profile="cisco_ios", username="u", secret="s", auth_type="password",
                pinned_fingerprint=collector.fingerprint(t.key), factory=_factory(t))
    args.update(kw)
    return collector.collect(**args)


def test_collect_returns_config_and_appends_extra_output_as_comments():
    t = FakeTransport(outputs={"show running-config": CONFIG, "show version": "Cisco IOS XE 17.9.4\nuptime 1 day"})
    text = _run(t)
    assert text.startswith(CONFIG) and "! --- show version ---" in text and "! Cisco IOS XE 17.9.4" in text
    assert [x for x in t.log if x != "host_key"] == [("login", "u", "password"), ("run", "show running-config"), ("run", "show version")]
    assert t.closed


def test_a_wrong_host_key_stops_before_any_credential_is_offered():
    t = FakeTransport(outputs={"show running-config": CONFIG})
    with pytest.raises(collector.CollectError, match="does not match"):
        _run(t, pinned_fingerprint=collector.fingerprint(b"some-other-key"))
    assert not any(isinstance(x, tuple) and x[0] == "login" for x in t.log) and t.closed


def test_collect_refuses_missing_pin_unknown_profile_empty_output_and_auth_failure():
    t = FakeTransport(outputs={"show running-config": CONFIG})
    with pytest.raises(collector.CollectError, match="pinned"):
        _run(t, pinned_fingerprint="")
    with pytest.raises(collector.CollectError, match="profile"):
        _run(t, profile="hp_comware")
    with pytest.raises(collector.CollectError, match="empty"):
        _run(FakeTransport(outputs={"show running-config": "  \n"}))
    t2 = FakeTransport(fail_login=True)
    with pytest.raises(collector.CollectError, match="authentication failed"):
        _run(t2)
    assert t2.closed and not any(isinstance(x, tuple) and x[0] == "run" for x in t2.log)


def test_scan_host_key_returns_the_fingerprint_without_logging_in():
    t = FakeTransport(key=b"k1")
    assert collector.scan_host_key("127.0.0.1", 22, _factory(t)) == collector.fingerprint(b"k1")
    assert t.log == ["host_key"] and t.closed


# ---------------------------------------------------------------- vault + API + RBAC
@pytest.fixture
def api(monkeypatch):
    monkeypatch.setattr(cfg, "REQUIRE_AUTH", True)

    def hdr(role):
        email = f"{role.lower()}-{uuid.uuid4().hex[:8]}@example.com"
        sec.create_user(email, role.title(), PW, role, org_id=cfg.DEFAULT_ORG_ID)
        r = client.post("/api/v1/auth/login", json={"email": email, "password": PW})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['data']['access_token']}"}
    return {r: hdr(r) for r in (rbac.VIEWER, rbac.AUDITOR, rbac.ADMIN)}


def _asset(h):
    r = client.post("/api/v1/assets", json={"name": "col-" + uuid.uuid4().hex[:6]}, headers=h)
    assert r.status_code in (200, 201), r.text
    return r.json()["data"]["asset_id"]


def test_credentials_are_encrypted_never_returned_and_admin_only(api):
    body = {"name": "n-" + uuid.uuid4().hex[:6], "username": "netops", "secret": "Sup3r-Secret-Dev-Pw", "auth_type": "password"}
    for role in (rbac.VIEWER, rbac.AUDITOR):
        assert client.post("/api/v1/collection/credentials", json=body, headers=api[role]).status_code == 403
        assert client.get("/api/v1/collection/credentials", headers=api[role]).status_code == 403
    r = client.post("/api/v1/collection/credentials", json=body, headers=api[rbac.ADMIN])
    assert r.status_code == 200 and "secret" not in r.text and "Sup3r" not in r.text
    cid = r.json()["data"]["credential_id"]
    listing = client.get("/api/v1/collection/credentials", headers=api[rbac.ADMIN])
    assert "Sup3r" not in listing.text and any(c["credential_id"] == cid for c in listing.json()["data"]["items"])
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT secret_enc FROM device_credentials WHERE credential_id=%s", (cid,))
        raw = cur.fetchone()[0]
    assert raw.startswith("enc:v1:") and "Sup3r" not in raw                # ciphertext at rest
    assert client.post("/api/v1/collection/credentials", json=body, headers=api[rbac.ADMIN]).status_code == 400   # duplicate name
    assert client.delete(f"/api/v1/collection/credentials/{cid}", headers=api[rbac.AUDITOR]).status_code == 403
    assert client.delete(f"/api/v1/collection/credentials/{cid}", headers=api[rbac.ADMIN]).status_code == 200
    assert client.delete(f"/api/v1/collection/credentials/{cid}", headers=api[rbac.ADMIN]).status_code == 404


def _cred(api, secret="pw"):
    r = client.post("/api/v1/collection/credentials", headers=api[rbac.ADMIN],
                    json={"name": "c-" + uuid.uuid4().hex[:6], "username": "netops", "secret": secret})
    return r.json()["data"]["credential_id"]


def test_target_configuration_rules(api):
    a = _asset(api[rbac.AUDITOR])
    cid = _cred(api)
    body = {"host": "127.0.0.1", "port": 22, "profile": "cisco_ios", "credential_id": cid, "host_key": "SHA256:" + "A" * 43}
    url = f"/api/v1/assets/{a}/collection"
    assert client.put(url, json=body, headers=api[rbac.AUDITOR]).status_code == 403     # cannot aim a credential at a host
    assert client.get(url, headers=api[rbac.VIEWER]).status_code == 404
    assert client.put(url, json={**body, "profile": "hp"}, headers=api[rbac.ADMIN]).status_code == 400
    assert client.put(url, json={**body, "host": "169.254.169.254"}, headers=api[rbac.ADMIN]).status_code == 400
    assert client.put(url, json={**body, "credential_id": "CRD-nope"}, headers=api[rbac.ADMIN]).status_code == 400
    assert client.put(f"/api/v1/assets/AST-missing/collection", json=body, headers=api[rbac.ADMIN]).status_code == 404
    assert client.put(url, json={**body, "host_key": "x"}, headers=api[rbac.ADMIN]).status_code == 422     # pin is mandatory
    ok = client.put(url, json=body, headers=api[rbac.ADMIN])
    assert ok.status_code == 200 and ok.json()["data"]["host_key"].startswith("SHA256:") and "secret" not in ok.text
    assert client.get(url, headers=api[rbac.VIEWER]).json()["data"]["host"] == "127.0.0.1"
    assert client.get("/api/v1/collection/profiles", headers=api[rbac.VIEWER]).status_code == 200


def test_collect_endpoint_needs_a_complete_target_then_queues_a_job(api):
    a = _asset(api[rbac.AUDITOR])
    assert client.post(f"/api/v1/assets/{a}/collect", json={}, headers=api[rbac.AUDITOR]).status_code == 400
    cid = _cred(api)
    client.put(f"/api/v1/assets/{a}/collection", headers=api[rbac.ADMIN],
               json={"host": "127.0.0.1", "profile": "cisco_ios", "credential_id": cid, "host_key": "SHA256:" + "A" * 43})
    assert client.post(f"/api/v1/assets/{a}/collect", json={}, headers=api[rbac.VIEWER]).status_code == 403
    r = client.post(f"/api/v1/assets/{a}/collect", json={"audit": False}, headers=api[rbac.AUDITOR])
    assert r.status_code == 200 and r.json()["data"]["job_id"].startswith("JOB-")


def test_scan_endpoint_is_admin_only_and_refuses_bad_targets(api, monkeypatch):
    a = _asset(api[rbac.AUDITOR])
    url = f"/api/v1/assets/{a}/collection/scan-host-key"
    assert client.post(url, json={"host": "127.0.0.1"}, headers=api[rbac.AUDITOR]).status_code == 403
    assert client.post(url, json={"host": "169.254.169.254"}, headers=api[rbac.ADMIN]).status_code == 400
    monkeypatch.setattr(collector, "_default_factory", _factory(FakeTransport(key=b"scan")))
    r = client.post(url, json={"host": "127.0.0.1", "port": 22}, headers=api[rbac.ADMIN])
    assert r.status_code == 200 and r.json()["data"]["fingerprint"] == collector.fingerprint(b"scan")


def test_job_handler_collects_registers_and_audits_the_configuration(api, monkeypatch):
    a = _asset(api[rbac.AUDITOR])
    cid = _cred(api, "device-pw")
    t = FakeTransport(key=b"lab-key", outputs={"show running-config": CONFIG, "show version": "Cisco IOS XE 17.9.4"})
    monkeypatch.setattr(collector, "_default_factory", _factory(t))
    client.put(f"/api/v1/assets/{a}/collection", headers=api[rbac.ADMIN],
               json={"host": "127.0.0.1", "profile": "cisco_ios", "credential_id": cid, "host_key": collector.fingerprint(b"lab-key")})
    from app.core import tenancy
    with tenancy.use_org(cfg.DEFAULT_ORG_ID):
        out = job_handlers.collect({"payload": {"asset_id": a, "audit": True}})
        assert out["configuration_id"].startswith("CFG-") and out["detected_vendor"] and out["audit"]["audit_id"]
        assert ("login", "netops", "password") in t.log
        tgt = collection.get_target(a)
        assert tgt["last_status"] == "OK" and tgt["last_collected_at"] and not tgt["last_error"]
        # a replaced device (different host key) fails permanently and records the reason, without logging in
        t2 = FakeTransport(key=b"other-key", outputs={"show running-config": CONFIG})
        monkeypatch.setattr(collector, "_default_factory", _factory(t2))
        with pytest.raises(job_handlers.PermanentJobError, match="does not match"):
            job_handlers.collect({"payload": {"asset_id": a, "audit": False}})
        assert not any(isinstance(x, tuple) and x[0] == "login" for x in t2.log)
        assert "does not match" in collection.get_target(a)["last_error"]
        with pytest.raises(job_handlers.PermanentJobError, match="asset not found"):
            job_handlers.collect({"payload": {"asset_id": "AST-nope"}})
        with pytest.raises(collector.CollectError, match="no collection target"):
            collection.collect_now(_asset(api[rbac.AUDITOR]))


def test_collection_cannot_use_another_organisations_credential(api):
    from app.core import tenancy
    with dbmod.get_conn() as conn:
        conn.cursor().execute("INSERT INTO organizations (org_id, name) VALUES ('ORG-COL-X', 'x') ON CONFLICT DO NOTHING")
    with tenancy.use_org("ORG-COL-X"):
        other = collection.create_credential("x-" + uuid.uuid4().hex[:6], "u", "pw", "password", None)["credential_id"]
    a = _asset(api[rbac.AUDITOR])
    r = client.put(f"/api/v1/assets/{a}/collection", headers=api[rbac.ADMIN],
                   json={"host": "127.0.0.1", "profile": "cisco_ios", "credential_id": other, "host_key": "SHA256:" + "A" * 43})
    assert r.status_code == 400
    with tenancy.use_org(cfg.DEFAULT_ORG_ID):
        assert all(c["credential_id"] != other for c in collection.list_credentials())
        assert collection.delete_credential(other) is False
    with pytest.raises(ValueError):
        collection.create_credential("bad", "u", "pw", "token", None)
    with pytest.raises(ValueError):
        collection.create_credential("bad", "u", "", "password", None)


# ---------------------------------------------------------------- real SSH (paramiko) ---------------------------------
paramiko = pytest.importorskip("paramiko")


class _SSHServer(paramiko.ServerInterface):
    def __init__(self, outputs, log):
        self.outputs, self.log = outputs, log

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self.log.append(("auth", username))
        return paramiko.AUTH_SUCCESSFUL if (username, password) == ("netops", "device-pw") else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode()
        self.log.append(("exec", cmd))

        def send():
            time.sleep(0.05)                      # a real device answers the exec request first, then streams output
            channel.sendall(self.outputs.get(cmd, "").encode())
            channel.send_exit_status(0)
            channel.close()
        threading.Thread(target=send, daemon=True).start()
        return True


@pytest.fixture
def ssh_device():
    host_key = paramiko.RSAKey.generate(2048)
    log, outputs = [], {"show running-config": CONFIG, "show version": "Cisco IOS XE 17.9.4\n"}
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    stop = threading.Event()

    def serve():
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except OSError:
                continue
            t = paramiko.Transport(conn)
            t.add_server_key(host_key)
            try:
                t.start_server(server=_SSHServer(outputs, log))
            except Exception:
                pass
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    yield {"port": sock.getsockname()[1], "log": log, "outputs": outputs, "fp": collector.fingerprint(host_key.asbytes())}
    stop.set()
    sock.close()


def test_real_ssh_collection_with_a_pinned_key(ssh_device):
    port = ssh_device["port"]
    assert collector.scan_host_key("127.0.0.1", port) == ssh_device["fp"]
    assert ssh_device["log"] == []                                                # scanning never authenticates
    text = collector.collect(host="127.0.0.1", port=port, profile="cisco_ios", username="netops", secret="device-pw",
                             auth_type="password", pinned_fingerprint=ssh_device["fp"])
    assert text.startswith(CONFIG) and "! Cisco IOS XE 17.9.4" in text
    assert ssh_device["log"] == [("auth", "netops"), ("exec", "show running-config"), ("exec", "show version")]


def test_real_ssh_wrong_pin_never_reaches_authentication(ssh_device):
    with pytest.raises(collector.CollectError, match="does not match"):
        collector.collect(host="127.0.0.1", port=ssh_device["port"], profile="cisco_ios", username="netops",
                          secret="device-pw", auth_type="password", pinned_fingerprint=collector.fingerprint(b"impostor"))
    assert ssh_device["log"] == []


def test_real_ssh_bad_password_and_output_cap(ssh_device, monkeypatch):
    with pytest.raises(collector.CollectError, match="authentication failed"):
        collector.collect(host="127.0.0.1", port=ssh_device["port"], profile="cisco_ios", username="netops",
                          secret="wrong", auth_type="password", pinned_fingerprint=ssh_device["fp"])
    ssh_device["outputs"]["show running-config"] = "x" * 5000
    monkeypatch.setattr(cfg, "COLLECT_MAX_BYTES", 1000)
    with pytest.raises(collector.CollectError, match="COLLECT_MAX_BYTES"):
        collector.collect(host="127.0.0.1", port=ssh_device["port"], profile="cisco_ios", username="netops",
                          secret="device-pw", auth_type="password", pinned_fingerprint=ssh_device["fp"])


def test_real_ssh_unreachable_and_bad_key_material(ssh_device):
    with pytest.raises(collector.CollectError):
        collector.scan_host_key("127.0.0.1", 1)                                    # nothing listens on port 1
    t = collector.ParamikoTransport("127.0.0.1", ssh_device["port"], 5.0)
    try:
        with pytest.raises(collector.CollectError, match="private key"):
            t.login("netops", "not a key", "key")
    finally:
        t.close()
