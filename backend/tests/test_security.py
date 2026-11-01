"""Security regression suite: auth hardening, RBAC, tenancy, encryption at rest,
redaction, regex safety, artifact integrity and the external-LLM gate.

Runs against the disposable test database (see conftest.py)."""
import re
import time
import uuid

from tests.conftest import system_scope
import psycopg
import pytest
from fastapi.testclient import TestClient

from app.core import auditlog, crypto, rbac, tenancy
from app.core import config as cfg
from app.core import db as dbmod
from app.core import persist
from app.core import security as sec
from app.main import app

client = TestClient(app)
STRONG = "Str0ng!Passw0rd#1"


@pytest.fixture(autouse=True)
def _auth_on(monkeypatch):
    """Every test in this module runs with authentication enforced."""
    monkeypatch.setattr(cfg, "REQUIRE_AUTH", True)
    sec.reset_throttle()
    yield
    tenancy.set_org(None)


def _org(org_id: str) -> str:
    with dbmod.get_conn() as conn:
        conn.cursor().execute("INSERT INTO organizations (org_id, name) VALUES (%s, %s) "
                              "ON CONFLICT (org_id) DO NOTHING", (org_id, org_id))
    return org_id


def _user(role: str, org: str = cfg.DEFAULT_ORG_ID, pw: str = STRONG) -> dict:
    email = f"{role.lower()}-{uuid.uuid4().hex[:8]}@example.com"
    sec.create_user(email, role.title(), pw, role, org_id=org)
    return {"email": email, "password": pw}


def _login(creds: dict):
    return client.post("/api/v1/auth/login", json=creds)


def _headers(role: str = rbac.ADMIN, org: str = cfg.DEFAULT_ORG_ID) -> dict:
    r = _login(_user(role, org))
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['data']['access_token']}"}


# ----------------------------------------------------------------- config guards
def test_production_config_validation(monkeypatch):
    monkeypatch.setattr(cfg, "ENV", "production")
    monkeypatch.setattr(cfg, "JWT_SECRET", "change-me-dev-secret")
    monkeypatch.setattr(cfg, "REQUIRE_AUTH", False)
    monkeypatch.setattr(cfg, "ADMIN_PASSWORD", "admin123")
    monkeypatch.setattr(cfg, "CORS_ORIGINS", ["*"])
    monkeypatch.setattr(cfg, "TRUSTED_HOSTS", ["*"])
    monkeypatch.setattr(cfg, "DATA_ENCRYPTION_KEYS", [])
    monkeypatch.setattr(cfg, "DATABASE_URL", "")
    problems = " | ".join(cfg.validate_production())
    for needle in ("JWT_SECRET", "REQUIRE_AUTH", "ADMIN_PASSWORD", "CORS_ORIGINS",
                   "TRUSTED_HOSTS", "DATA_ENCRYPTION_KEYS", "DATABASE_URL"):
        assert needle in problems
    monkeypatch.setattr(cfg, "JWT_SECRET", "x" * 40)
    monkeypatch.setattr(cfg, "PASSWORD_HASH_ITERATIONS", 600000)    # the suite runs with 1000 for speed
    monkeypatch.setattr(cfg, "REQUIRE_AUTH", True)
    monkeypatch.setattr(cfg, "ADMIN_PASSWORD", STRONG)
    monkeypatch.setattr(cfg, "CORS_ORIGINS", ["https://app.example.com"])
    monkeypatch.setattr(cfg, "TRUSTED_HOSTS", ["api.example.com"])
    monkeypatch.setattr(cfg, "DATA_ENCRYPTION_KEYS", [crypto.generate_key()])
    monkeypatch.setattr(cfg, "DATABASE_URL", "postgresql://x")
    assert cfg.validate_production() == []


def test_secure_by_default_and_headers():
    assert client.get("/api/v1/dashboard/summary").status_code == 401  # no token, auth required
    r = client.get("/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    api = client.get("/api/v1/dashboard/summary")
    assert api.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in api.headers["Content-Security-Policy"]


def test_request_id_is_sanitised():
    r = client.get("/health", headers={"X-Request-ID": "evil\r\nSet-Cookie: x=1"})
    assert "\n" not in r.headers["X-Request-ID"] and r.headers["X-Request-ID"] != "evil"


# ---------------------------------------------------------------------- passwords
def test_password_policy():
    assert sec.password_problems("short1A!")
    assert sec.password_problems("alllowercaseletters")
    assert sec.password_problems("Password123!x")[0:0] == []  # long + mixed passes length/class
    assert not sec.password_problems(STRONG, "x@example.com")
    assert sec.password_problems("johnsmith-Passw0rd!", "johnsmith@example.com")  # contains the e-mail name
    with pytest.raises(ValueError):
        sec.create_user("weak@example.com", "Weak", "weak", rbac.VIEWER)


def test_hash_upgrade_on_login():
    creds = _user(rbac.VIEWER)
    old = sec._hash(creds["password"], 10)  # legacy low-iteration hash
    with dbmod.get_conn() as conn:
        conn.cursor().execute("UPDATE users SET password_hash=%s WHERE email=%s", (old, creds["email"]))
    assert _login(creds).status_code == 200
    assert sec._user_by_email(creds["email"])["password_hash"].split("$")[1] == str(cfg.PASSWORD_HASH_ITERATIONS)


# ------------------------------------------------------------- lockout / throttling
def test_account_lockout_and_unlock():
    creds = _user(rbac.VIEWER)
    for _ in range(cfg.LOGIN_MAX_ATTEMPTS):
        assert _login({**creds, "password": "wrong-password"}).status_code == 401
    r = _login(creds)  # correct password, but the account is now locked
    assert r.status_code == 429
    with dbmod.get_conn() as conn:
        conn.cursor().execute("UPDATE users SET locked_until=now() - interval '1 minute' WHERE email=%s",
                              (creds["email"],))
    assert _login(creds).status_code == 200
    assert sec._user_by_email(creds["email"])["failed_attempts"] == 0


def test_unknown_user_gets_same_error_as_bad_password():
    creds = _user(rbac.VIEWER)
    a = _login({"email": "nobody-here@example.com", "password": "x" * 12})
    b = _login({**creds, "password": "wrong-password"})
    assert a.status_code == b.status_code == 401
    assert a.json()["error"]["message"] == b.json()["error"]["message"]


def test_ip_throttle(monkeypatch):
    monkeypatch.setattr(cfg, "LOGIN_IP_MAX_PER_MINUTE", 3)
    codes = [_login({"email": f"nobody{i}@example.com", "password": "x" * 12}).status_code for i in range(5)]
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429]


# ------------------------------------------------------------------- token lifecycle
def test_logout_revokes_token():
    h = _headers(rbac.VIEWER)
    assert client.get("/api/v1/auth/me", headers=h).status_code == 200
    assert client.post("/api/v1/auth/logout", headers=h).status_code == 200
    r = client.get("/api/v1/auth/me", headers=h)
    assert r.status_code == 401 and "revoked" in r.json()["error"]["message"].lower()
    assert client.get("/api/v1/assets", headers=h).status_code == 401


def test_change_password_invalidates_other_sessions():
    creds = _user(rbac.AUDITOR)
    t1 = _login(creds).json()["data"]["access_token"]
    t2 = _login(creds).json()["data"]["access_token"]
    h1 = {"Authorization": f"Bearer {t1}"}
    new_pw = "An0ther!Strong#Pass"
    assert client.post("/api/v1/auth/change-password", headers=h1,
                       json={"current_password": "nope", "new_password": new_pw}).status_code == 400
    assert client.post("/api/v1/auth/change-password", headers=h1,
                       json={"current_password": creds["password"], "new_password": "weak"}).status_code == 400
    r = client.post("/api/v1/auth/change-password", headers=h1,
                    json={"current_password": creds["password"], "new_password": new_pw})
    assert r.status_code == 200
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {t2}"}).status_code == 401
    fresh = r.json()["data"]["access_token"]
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {fresh}"}).status_code == 200


def test_tampered_and_expired_tokens_rejected(monkeypatch):
    h = _headers(rbac.VIEWER)
    tok = h["Authorization"].split()[1]
    assert client.get("/api/v1/assets", headers={"Authorization": f"Bearer {tok[:-3]}abc"}).status_code == 401
    monkeypatch.setattr(cfg, "JWT_EXPIRE_MINUTES", -1)
    expired = sec.make_token(sec._user_by_email(_user(rbac.VIEWER)["email"]))["access_token"]
    assert client.get("/api/v1/assets", headers={"Authorization": f"Bearer {expired}"}).status_code == 401


def test_disabled_user_loses_access():
    admin = _headers(rbac.ADMIN)
    creds = _user(rbac.AUDITOR)
    tok = _login(creds).json()["data"]["access_token"]
    uid = sec._user_by_email(creds["email"])["id"]
    assert client.patch(f"/api/v1/admin/users/{uid}", headers=admin, json={"disabled": True}).status_code == 200
    assert client.get("/api/v1/assets", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
    assert _login(creds).status_code == 401


# ------------------------------------------------------------------------- RBAC
def test_every_api_route_enforces_permissions():
    """Behavioural sweep over EVERY documented route: anonymous -> 401, and a VIEWER token must
    get 403 on everything the matrix reserves for a higher role."""
    viewer = _headers(rbac.VIEWER)
    checked = privileged = 0
    for path, ops in app.openapi()["paths"].items():
        if not path.startswith("/api/v1/") or path.startswith("/api/v1/auth/"):
            continue  # meta probes are public; login/logout/me/change-password authenticate themselves
        url = re.sub(r"\{[^}]+\}", "X", path)
        for method in ops:
            if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                continue
            anon = client.request(method.upper(), url)
            assert anon.status_code == 401, f"{method.upper()} {path} reachable without a token ({anon.status_code})"
            needed = rbac.required_role(method, url)
            assert needed in rbac.ROLES
            if needed != rbac.VIEWER:
                r = client.request(method.upper(), url, headers=viewer)
                assert r.status_code == 403, f"{method.upper()} {path} should need {needed} ({r.status_code})"
                privileged += 1
            checked += 1
    assert checked > 50 and privileged > 15


def test_permission_matrix():
    assert rbac.required_role("GET", "/api/v1/assets") == rbac.VIEWER
    assert rbac.required_role("POST", "/api/v1/assets") == rbac.AUDITOR
    assert rbac.required_role("POST", "/api/v1/training/TR-1/approve") == rbac.APPROVER
    assert rbac.required_role("POST", "/api/v1/remediation/F-1/apply") == rbac.APPROVER
    assert rbac.required_role("DELETE", "/api/v1/assets/AST-1") == rbac.APPROVER
    assert rbac.required_role("POST", "/api/v1/vulnerabilities/sync") == rbac.ADMIN
    assert rbac.required_role("GET", "/api/v1/admin/users") == rbac.ADMIN
    assert rbac.required_role("POST", "/api/v1/detection/vendor") == rbac.VIEWER
    assert rbac.has_role("ADMIN", "VIEWER") and not rbac.has_role("VIEWER", "AUDITOR")
    assert not rbac.has_role("", "VIEWER") and not rbac.has_role("ROOT", "VIEWER")


def test_roles_enforced_end_to_end():
    viewer, auditor = _headers(rbac.VIEWER), _headers(rbac.AUDITOR)
    approver, admin = _headers(rbac.APPROVER), _headers(rbac.ADMIN)
    body = {"name": f"rbac-{uuid.uuid4().hex[:6]}", "vendor": "cisco"}
    assert client.get("/api/v1/assets", headers=viewer).status_code == 200
    assert client.post("/api/v1/assets", headers=viewer, json=body).status_code == 403
    r = client.post("/api/v1/assets", headers=auditor, json=body)
    assert r.status_code == 200
    aid = r.json()["data"]["asset_id"]
    # approval-level actions
    assert client.post("/api/v1/training/TR-X/approve", headers=auditor,
                       json={"canonical_property": "SSH.VERSION"}).status_code == 403
    assert client.post("/api/v1/training/TR-X/approve", headers=approver,
                       json={"canonical_property": "SSH.VERSION"}).status_code == 404  # authorised, not found
    assert client.delete(f"/api/v1/assets/{aid}", headers=auditor).status_code == 403
    assert client.delete(f"/api/v1/assets/{aid}", headers=approver).status_code == 200
    # admin-only
    for path in ("/api/v1/admin/users", "/api/v1/admin/audit-log"):
        assert client.get(path, headers=approver).status_code == 403
        assert client.get(path, headers=admin).status_code == 200
    assert client.post("/api/v1/vulnerabilities/sync", headers=approver, json={}).status_code == 403


def test_admin_user_management():
    admin = _headers(rbac.ADMIN)
    email = f"new-{uuid.uuid4().hex[:6]}@example.com"
    assert client.post("/api/v1/admin/users", headers=admin,
                       json={"email": email, "name": "N", "password": "weak"}).status_code == 400
    r = client.post("/api/v1/admin/users", headers=admin,
                    json={"email": email, "name": "N", "password": STRONG, "role": "AUDITOR"})
    assert r.status_code == 200 and "password_hash" not in r.text
    assert client.post("/api/v1/admin/users", headers=admin,
                       json={"email": email, "name": "N", "password": STRONG}).status_code == 400  # duplicate
    uid = r.json()["data"]["id"]
    assert client.patch(f"/api/v1/admin/users/{uid}", headers=admin, json={"role": "ROOT"}).status_code == 400
    assert client.patch(f"/api/v1/admin/users/{uid}", headers=admin, json={}).status_code == 400
    assert client.patch(f"/api/v1/admin/users/{uid}", headers=admin, json={"role": "APPROVER"}).status_code == 200
    assert client.patch(f"/api/v1/admin/users/{uid}", headers=admin,
                        json={"new_password": "weak"}).status_code == 400
    assert client.patch(f"/api/v1/admin/users/{uid}", headers=admin,
                        json={"new_password": "Reset!Passw0rd#2"}).status_code == 200
    assert client.patch("/api/v1/admin/users/USR-NOPE", headers=admin, json={"disabled": True}).status_code == 404
    listing = client.get("/api/v1/admin/users", headers=admin).json()["data"]["items"]
    assert any(u["email"] == email for u in listing) and all("password_hash" not in u for u in listing)
    me = sec._user_by_email(client.get("/api/v1/auth/me", headers=admin).json()["data"]["email"])
    assert client.patch(f"/api/v1/admin/users/{me['id']}", headers=admin, json={"role": "VIEWER"}).status_code == 400
    assert client.patch(f"/api/v1/admin/users/{me['id']}", headers=admin, json={"disabled": True}).status_code == 400


# ------------------------------------------------------------------------ tenancy
def test_tenant_isolation():
    a, b = _org("ORG-A"), _org("ORG-B")
    ha, hb = _headers(rbac.ADMIN, a), _headers(rbac.ADMIN, b)
    r = client.post("/api/v1/assets", headers=ha, json={"name": f"secret-a-{uuid.uuid4().hex[:6]}"})
    aid = r.json()["data"]["asset_id"]
    assert client.get(f"/api/v1/assets/{aid}", headers=ha).status_code == 200
    assert client.get(f"/api/v1/assets/{aid}", headers=hb).status_code == 404
    assert aid not in client.get("/api/v1/assets?page_size=100", headers=hb).text
    assert client.patch(f"/api/v1/assets/{aid}", headers=hb, json={"model": "x"}).status_code == 404
    assert client.delete(f"/api/v1/assets/{aid}", headers=hb).status_code == 404
    # uploading B's data against A's asset must fail
    up = client.post("/api/v1/configurations/upload", headers=hb, data={"asset_id": aid},
                     files={"file": ("c.txt", b"hostname X\n", "text/plain")})
    assert up.status_code == 404
    # B's admin cannot see or touch A's users or audit trail
    uids_a = {u["id"] for u in client.get("/api/v1/admin/users", headers=ha).json()["data"]["items"]}
    uids_b = {u["id"] for u in client.get("/api/v1/admin/users", headers=hb).json()["data"]["items"]}
    assert uids_a.isdisjoint(uids_b)
    assert client.patch(f"/api/v1/admin/users/{next(iter(uids_a))}", headers=hb,
                        json={"disabled": True}).status_code == 404


def test_persist_refuses_cross_org_overwrite():
    _org("ORG-C")
    rec = {"asset_id": f"AST-{uuid.uuid4().hex[:8].upper()}", "name": "owned-by-default", "status": "ACTIVE"}
    persist.save("assets", dict(rec))
    with tenancy.use_org("ORG-C"):
        with pytest.raises(PermissionError):
            persist.save("assets", {**rec, "name": "hijacked"})
        assert persist.get("assets", rec["asset_id"]) is None
        assert persist.count("assets", status="ACTIVE") == persist.count("assets", status="ACTIVE")
    assert persist.get("assets", rec["asset_id"])["name"] == "owned-by-default"


def test_persist_rejects_unsafe_query_parts():
    with pytest.raises(ValueError):
        persist.find("assets", **{"name; DROP TABLE assets": "x"})
    with pytest.raises(ValueError):
        persist.find("assets", order="ASC; DROP TABLE assets")
    with pytest.raises(ValueError):
        persist.select("assets", ["asset_id; DROP TABLE assets"])
    with pytest.raises(ValueError):
        persist.select("assets", ["asset_id"], order="created_at; DROP TABLE assets")


# ------------------------------------------------------ encryption + redaction at rest
SECRET_CFG = (b"hostname R1\nenable secret 5 $1$abcd$HASHVALUE\nsnmp-server community TopSecret123 RO\n"
              b"username admin privilege 15 secret 9 $9$deadbeef\nline vty 0 4\n password 7 0822455D0A16\n"
              b"ip ssh version 2\n")


def test_config_encrypted_at_rest_and_redacted_for_viewers():
    admin = _headers(rbac.ADMIN)
    aid = client.post("/api/v1/assets", headers=admin,
                      json={"name": f"enc-{uuid.uuid4().hex[:6]}"}).json()["data"]["asset_id"]
    up = client.post("/api/v1/configurations/upload", headers=admin, data={"asset_id": aid},
                     files={"file": ("r.txt", SECRET_CFG, "text/plain")})
    assert up.status_code == 200
    cid = up.json()["data"]["configuration_id"]
    with psycopg.connect(dbmod.DATABASE_URL) as raw:
        col, js = system_scope(raw).execute("SELECT config_text, data->>'config_text' FROM configurations "
                              "WHERE configuration_id=%s", (cid,)).fetchone()
    assert col.startswith("enc:v1:") and js.startswith("enc:v1:")
    assert "TopSecret123" not in col and "TopSecret123" not in js
    plain = client.get(f"/api/v1/configurations/{cid}", headers=admin).json()["data"]["config_text"]
    assert "TopSecret123" in plain  # authorised roles still get the original


def test_viewer_sees_masked_config():
    admin = _headers(rbac.ADMIN)
    aid = client.post("/api/v1/assets", headers=admin,
                      json={"name": f"mask-{uuid.uuid4().hex[:6]}"}).json()["data"]["asset_id"]
    cid = client.post("/api/v1/configurations/upload", headers=admin, data={"asset_id": aid},
                      files={"file": ("r.txt", SECRET_CFG, "text/plain")}).json()["data"]["configuration_id"]
    r = client.get(f"/api/v1/configurations/{cid}", headers=_headers(rbac.VIEWER))
    assert r.status_code == 200
    text = r.json()["data"]["config_text"]
    assert "TopSecret123" not in text and "HASHVALUE" not in text and "deadbeef" not in text
    assert "<REDACTED>" in text and "ip ssh version 2" in text


def test_crypto_roundtrip_rotation_and_tamper(monkeypatch):
    token = crypto.encrypt("snmp-server community xyz")
    assert token.startswith(crypto.PREFIX) and crypto.decrypt(token) == "snmp-server community xyz"
    assert crypto.encrypt(token) == token                      # idempotent
    assert crypto.decrypt("legacy plaintext") == "legacy plaintext"
    assert crypto.encrypt(None) is None
    old_key, new_key = crypto.generate_key(), crypto.generate_key()
    monkeypatch.setattr(cfg, "DATA_ENCRYPTION_KEYS", [old_key])
    crypto.reset()
    t_old = crypto.encrypt("value")
    monkeypatch.setattr(cfg, "DATA_ENCRYPTION_KEYS", [new_key, old_key])  # rotation: new key first
    crypto.reset()
    assert crypto.decrypt(t_old) == "value"                    # old rows still readable
    assert crypto.encrypt("value") != t_old
    monkeypatch.setattr(cfg, "DATA_ENCRYPTION_KEYS", [crypto.generate_key()])
    crypto.reset()
    with pytest.raises(RuntimeError):
        crypto.decrypt(t_old)                                   # wrong key -> loud failure
    monkeypatch.setattr(cfg, "ENV", "production")
    monkeypatch.setattr(cfg, "DATA_ENCRYPTION_KEYS", [])
    crypto.reset()
    with pytest.raises(RuntimeError):
        crypto.encrypt("x")                                     # production never falls back to the dev key
    monkeypatch.undo()
    crypto.reset()


def test_redaction_rules():
    from app.core.redact import contains_secret, redact_secrets
    cases = {
        "enable secret 5 $1$abc$HASH": "enable secret 5 <REDACTED>",
        "snmp-server community public RO": "snmp-server community <REDACTED> RO",
        "username bob privilege 15 secret 9 $9$zz": "username bob privilege 15 secret 9 <REDACTED>",
        " password 7 0822455D0A16": " password 7 <REDACTED>",
        "tacacs-server host 10.0.0.1 key 7 ABCDEF": "tacacs-server host 10.0.0.1 key 7 <REDACTED>",
        "crypto isakmp key MySharedKey address 1.1.1.1": "crypto isakmp key <REDACTED> address 1.1.1.1",
        'set password ENC abcdef': "set password ENC <REDACTED>",
        "<phash>$1$xyz</phash>": "<phash><REDACTED></phash>",
    }
    for src, want in cases.items():
        assert redact_secrets(src) == want, src
    assert contains_secret("snmp-server community abc") and not contains_secret("ip ssh version 2")
    assert redact_secrets("ip ssh version 2\nhostname R1") == "ip ssh version 2\nhostname R1"
    assert "PRIVATE KEY-----<REDACTED>" in redact_secrets(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----")


# ------------------------------------------------------- learned-mapping safety + DB
def test_safe_pattern_neutralises_regex_injection():
    from app.api.v1.training import build_safe_pattern, validate_pattern
    nasty = "snmp-server community (a+)+$ [x] .* RO"
    pat = build_safe_pattern(nasty)
    validate_pattern(pat, nasty)
    assert re.search(pat, nasty, re.I)
    assert not re.search(pat, "snmp-server community aaaa x RO", re.I)    # metacharacters are literal
    t0 = time.perf_counter()
    re.search(pat, "snmp-server community " + "a" * 50000, re.I)           # no catastrophic backtracking
    assert time.perf_counter() - t0 < 0.5
    with pytest.raises(ValueError):
        build_safe_pattern("   ")
    with pytest.raises(ValueError):
        validate_pattern("(", "x")
    with pytest.raises(ValueError):
        validate_pattern("x" * 500, "x")
    with pytest.raises(ValueError):
        validate_pattern("^other$", "something else")


def _training_item(raw: str, vendor="CISCO") -> str:
    tid = "TR-" + uuid.uuid4().hex[:8].upper()
    persist.save("training", {"training_id": tid, "vendor": vendor, "platform": "ios-xe",
                              "raw_command": raw, "context": [], "status": "PENDING",
                              "created_at": time.time()})
    return tid


def test_approved_mapping_is_db_backed_applied_and_tenant_scoped():
    from app.parsers import canonical as canon
    approver = _headers(rbac.APPROVER)
    line = f"service weird-feature-{uuid.uuid4().hex[:6]} enable (x+)"
    tid = _training_item(line)
    bad = client.post(f"/api/v1/training/{tid}/approve", headers=approver,
                      json={"canonical_property": "NOT.A.REAL.PROPERTY", "canonical_value": True})
    assert bad.status_code == 400
    bad = client.post(f"/api/v1/training/{tid}/approve", headers=approver,
                      json={"canonical_property": "TELNET.ENABLED", "canonical_value": {"a": 1}})
    assert bad.status_code == 400
    ok = client.post(f"/api/v1/training/{tid}/approve", headers=approver,
                     json={"canonical_property": "TELNET.ENABLED", "canonical_value": True, "comment": "t"})
    assert ok.status_code == 200, ok.text
    assert client.post(f"/api/v1/training/{tid}/approve", headers=approver,
                       json={"canonical_property": "TELNET.ENABLED", "canonical_value": True}).status_code == 409
    row = persist.find("mappings", status="approved")[-1]
    assert row["vendor"] == "cisco" and row["approved_by"].endswith("@example.com")  # lower-cased + actor stamped
    flat = canon.parse_to_canonical(f"hostname R1\n{line}\n", "cisco")["flat_ir"]
    assert flat.get("TELNET.ENABLED") is True                  # applies on the next audit, no redeploy
    _org("ORG-D")
    with tenancy.use_org("ORG-D"):                              # another tenant never sees it
        other = canon.parse_to_canonical(f"hostname R1\n{line}\n", "cisco")["flat_ir"]
    assert "TELNET.ENABLED" not in other
    # duplicate approval of the same line for the same vendor is rejected
    tid2 = _training_item(line)
    assert client.post(f"/api/v1/training/{tid2}/approve", headers=approver,
                       json={"canonical_property": "TELNET.ENABLED", "canonical_value": True}).status_code == 409


def test_reject_stamps_actor():
    approver = _headers(rbac.APPROVER)
    tid = _training_item("some other line")
    r = client.post(f"/api/v1/training/{tid}/reject", headers=approver, json={"reason": "noise"})
    assert r.status_code == 200
    assert persist.get("training", tid)["rejected_by"].endswith("@example.com")


def test_remediation_approver_is_the_authenticated_user():
    approver = _headers(rbac.APPROVER)
    fid = "F-" + uuid.uuid4().hex[:6].upper()
    persist.save("findings", {"finding_id": fid, "audit_id": "AUD-X", "asset_id": "AST-X", "engine": "compliance",
                              "type": "COMPLIANCE", "title": "t", "severity": "HIGH", "status": "FAIL"})
    r = client.post(f"/api/v1/remediation/{fid}/approve", headers=approver,
                    json={"approved_by": "someone-else@evil.test", "comment": "ok"})
    assert r.status_code == 200
    assert r.json()["data"]["approved_by"] != "someone-else@evil.test"
    assert r.json()["data"]["approved_by"].endswith("@example.com")


# -------------------------------------------------------------- audit identity
def test_audit_ids_are_scoped_to_asset_and_org(monkeypatch):
    """Same config on two assets / two orgs must not share (and overwrite) one audit."""
    from app.services import audit_service
    seen = {}

    def fake_save(entity, rec):
        if entity == "audits":
            seen.setdefault("ids", []).append(rec["audit_id"])
        return rec

    monkeypatch.setattr(audit_service.db, "save", fake_save)
    monkeypatch.setattr(audit_service.db, "select", lambda *a, **k: [])
    text = "hostname R1\nip ssh version 2\n"
    kw = dict(configuration_id="CFG-1", config_text=text, frameworks=["CIS"], run_cve=False, run_pqc=False,
              run_security=False)
    audit_service.run_audit(asset_id="AST-ONE", **kw)
    audit_service.run_audit(asset_id="AST-ONE", **kw)
    audit_service.run_audit(asset_id="AST-TWO", **kw)
    with tenancy.use_org("ORG-E"):
        audit_service.run_audit(asset_id="AST-ONE", **kw)
    ids = seen["ids"]
    assert ids[0] == ids[1]                      # idempotent re-run on the same asset
    assert len({ids[0], ids[2], ids[3]}) == 3    # different asset / different org -> distinct audits


def test_audit_evidence_never_stores_secret_values():
    from app.services import audit_service
    out = {}
    import app.services.audit_service as svc

    def grab(entity, rec):
        if entity == "audits":
            out["rec"] = rec
        return rec

    old_save, old_select = svc.db.save, svc.db.select
    svc.db.save, svc.db.select = grab, (lambda *a, **k: [])
    try:
        audit_service.run_audit(asset_id="AST-R", configuration_id="CFG-R", config_text=SECRET_CFG.decode(),
                                frameworks=["CIS"], run_cve=False, run_pqc=False, run_security=False)
    finally:
        svc.db.save, svc.db.select = old_save, old_select
    blob = str(out["rec"]["provenance"]) + str(out["rec"]["unknown_lines"])
    assert "TopSecret123" not in blob and "HASHVALUE" not in blob and "0822455D0A16" not in blob


# ---------------------------------------------------------------------- audit trail
def test_audit_trail_records_actions_and_is_append_only():
    auditor, admin = _headers(rbac.AUDITOR), _headers(rbac.ADMIN)
    name = f"trail-{uuid.uuid4().hex[:6]}"
    assert client.post("/api/v1/assets", headers=auditor, json={"name": name}).status_code == 200
    assert client.post("/api/v1/assets", headers=_headers(rbac.VIEWER), json={"name": name}).status_code == 403
    items = client.get("/api/v1/admin/audit-log?limit=200", headers=admin).json()["data"]["items"]
    posts = [i for i in items if i["method"] == "POST" and i["path"] == "/api/v1/assets"]
    assert any(i["status"] == 200 and i["actor_email"] for i in posts)
    assert any(i["status"] == 403 for i in posts)              # denied attempts are recorded too
    assert any(i["action"] == "auth.login" for i in items)
    filt = client.get("/api/v1/admin/audit-log?action=auth.login", headers=admin).json()["data"]["items"]
    assert filt and all(i["action"] == "auth.login" for i in filt)
    with dbmod.get_conn() as conn:
        with pytest.raises(psycopg.errors.RaiseException):
            conn.cursor().execute("UPDATE audit_log SET action='tampered'")
    with dbmod.get_conn() as conn:
        with pytest.raises(psycopg.errors.RaiseException):
            conn.cursor().execute("DELETE FROM audit_log")


def test_audit_log_never_breaks_requests(monkeypatch):
    monkeypatch.setattr(dbmod, "get_conn", lambda: (_ for _ in ()).throw(RuntimeError("db down")))
    auditlog.record("x", method="POST", path="/p")           # swallowed, no exception
    assert auditlog.should_log("POST", "/api/v1/x") and not auditlog.should_log("GET", "/api/v1/assets")
    assert auditlog.should_log("GET", "/api/v1/reports/R-1/download")


# --------------------------------------------------------- artifacts + LLM gate
def test_artifact_integrity_guard(tmp_path, monkeypatch):
    from app.services import integration
    integration._ensure_bridge()
    from src.artifact_guard import ArtifactIntegrityError, load_verified, verify, write_manifest
    import joblib
    f = tmp_path / "model.pkl"
    joblib.dump({"a": 1}, f)
    monkeypatch.setenv("ARTIFACT_VERIFY", "strict")
    with pytest.raises(ArtifactIntegrityError):               # no manifest -> refuse
        verify(f)
    write_manifest(tmp_path)
    assert load_verified(f) == {"a": 1}
    f.write_bytes(f.read_bytes() + b"tamper")
    with pytest.raises(ArtifactIntegrityError):               # modified file -> refuse
        load_verified(f)
    joblib.dump({"a": 2}, tmp_path / "unlisted.pkl")
    with pytest.raises(ArtifactIntegrityError):               # not in manifest -> refuse
        verify(tmp_path / "unlisted.pkl")
    monkeypatch.setenv("ARTIFACT_VERIFY", "warn")
    verify(f)                                                  # warn mode only logs
    monkeypatch.setenv("ARTIFACT_VERIFY", "off")
    verify(f)
    # HMAC-authenticated manifest: an attacker who rewrites hashes still cannot forge the signature
    monkeypatch.setenv("ARTIFACT_VERIFY", "strict")
    monkeypatch.setenv("ARTIFACT_SIGNING_KEY", "k" * 32)
    write_manifest(tmp_path)
    verify(f)
    import json
    m = json.loads((tmp_path / "ARTIFACTS.sha256.json").read_text())
    m["files"]["model.pkl"] = "0" * 64
    (tmp_path / "ARTIFACTS.sha256.json").write_text(json.dumps(m))
    with pytest.raises(ArtifactIntegrityError):
        verify(f)


def test_shipped_artifacts_match_manifest(monkeypatch):
    from app.services import integration
    integration._ensure_bridge()
    from src.artifact_guard import verify
    monkeypatch.setenv("ARTIFACT_VERIFY", "strict")
    for p in sorted((cfg.MODELS_DIR / "artifacts").glob("*.pkl")):
        verify(p)


def test_external_llm_is_opt_in(monkeypatch):
    from app.services import integration
    integration._ensure_bridge()
    from llm_gateway import FeatherlessGateway
    ext = FeatherlessGateway(api_key="k", base_url="https://api.featherless.ai/v1")
    monkeypatch.delenv("ALLOW_EXTERNAL_LLM", raising=False)
    assert ext.online is False                                 # key alone is not enough
    r = ext.chat([{"role": "user", "content": "x"}])
    assert r.ok is False and r.offline is True
    monkeypatch.setenv("ALLOW_EXTERNAL_LLM", "true")
    assert ext.online is True
    assert FeatherlessGateway(api_key="", base_url="https://api.featherless.ai/v1").online is False
    monkeypatch.setenv("ALLOW_EXTERNAL_LLM", "false")
    assert FeatherlessGateway(api_key="", base_url="http://localhost:11434/v1").online is True   # local model
    assert FeatherlessGateway(api_key="", base_url="http://llm.internal:8000/v1").online is True
    assert FeatherlessGateway(api_key="k", base_url="https://evil.example/v1").online is False


def test_llm_payload_is_redacted_before_send(monkeypatch):
    from app.services import integration
    integration._ensure_bridge()
    import httpx
    from llm_gateway import FeatherlessGateway
    sent = {}

    class R:
        status_code = 200
        text = ""

        def json(self):
            return {"choices": [{"message": {"content": "{}"}}]}

    def fake_post(url, headers=None, json=None, timeout=None):
        sent["body"] = json
        return R()

    monkeypatch.setattr(httpx, "post", fake_post)
    gw = FeatherlessGateway(api_key="", base_url="http://localhost:11434/v1")
    gw.chat([{"role": "user", "content": "snmp-server community TopSecret123 RO\nenable secret 5 $1$x$HASH"}])
    body = str(sent["body"])
    assert "TopSecret123" not in body and "$1$x$HASH" not in body and "<REDACTED>" in body
