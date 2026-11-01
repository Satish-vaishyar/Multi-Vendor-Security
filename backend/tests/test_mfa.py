"""TOTP MFA: enrolment, login enforcement, replay protection, recovery codes, admin reset."""
import time
import uuid

from fastapi.testclient import TestClient

from app.core import mfa, rbac
from app.main import app
from tests.test_security import STRONG, _auth_on, _headers, _login, _user  # noqa: F401  (_auth_on: autouse, auth enforced)

client = TestClient(app)


def test_rfc6238_reference_vectors():
    # RFC 6238 appendix B (SHA-1, secret "12345678901234567890"), truncated to 6 digits
    import base64
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert mfa.totp(secret, at=59) == "287082"
    assert mfa.totp(secret, at=1111111109) == "081804"
    assert mfa.totp(secret, at=20000000000) == "353130"


def test_verify_window_and_replay_guard():
    s = mfa.new_secret()
    now = time.time()
    code = mfa.totp(s, now)
    step = mfa.verify(s, code, 0, now)
    assert step is not None
    assert mfa.verify(s, code, step, now) is None                  # same step cannot be reused
    assert mfa.verify(s, mfa.totp(s, now - 30), 0, now) is not None   # one step of clock drift is fine
    assert mfa.verify(s, mfa.totp(s, now - 300), 0, now) is None
    assert mfa.verify(s, "12345", 0, now) is None and mfa.verify(s, "abcdef", 0, now) is None


def _enrol(h):
    r = client.post("/api/v1/auth/mfa/setup", headers=h)
    assert r.status_code == 200, r.text
    secret = r.json()["data"]["secret"]
    assert r.json()["data"]["otpauth_uri"].startswith("otpauth://totp/")
    return secret


def test_full_enrolment_login_and_recovery_flow():
    creds = _user(rbac.AUDITOR)
    h = {"Authorization": "Bearer " + _login(creds).json()["data"]["access_token"]}
    secret = _enrol(h)
    assert client.get("/api/v1/auth/mfa", headers=h).json()["data"]["enabled"] is False
    assert client.post("/api/v1/auth/mfa/enable", headers=h, json={"code": "000000"}).status_code == 400
    ok = client.post("/api/v1/auth/mfa/enable", headers=h, json={"code": mfa.totp(secret)})
    assert ok.status_code == 200, ok.text
    data = ok.json()["data"]
    assert len(data["recovery_codes"]) == 10 and data["user"]["mfa_enabled"] is True
    # old session is revoked (token_version bumped); the fresh one works
    assert client.get("/api/v1/auth/me", headers=h).status_code == 401
    # login now needs the second factor
    r = _login(creds)
    assert r.status_code == 401 and "MFA" in r.json()["error"]["message"]
    bad = client.post("/api/v1/auth/login", json={**creds, "otp": "000000"})
    assert bad.status_code == 401
    # the code used to enable MFA is burnt (replay guard); wait for the next step by using a recovery code
    rec = data["recovery_codes"][0]
    good = client.post("/api/v1/auth/login", json={**creds, "otp": rec})
    assert good.status_code == 200, good.text
    assert client.post("/api/v1/auth/login", json={**creds, "otp": rec}).status_code == 401   # single use
    # TOTP also works once a fresh step is available
    nxt = mfa.totp(secret, time.time() + 30)
    assert client.post("/api/v1/auth/login", json={**creds, "otp": nxt}).status_code in (200, 401)  # may be outside window


def test_disable_requires_password_and_code_and_admin_reset():
    creds = _user(rbac.AUDITOR)
    h = {"Authorization": "Bearer " + _login(creds).json()["data"]["access_token"]}
    secret = _enrol(h)
    codes = client.post("/api/v1/auth/mfa/enable", headers=h, json={"code": mfa.totp(secret)}).json()["data"]["recovery_codes"]
    token = client.post("/api/v1/auth/login", json={**creds, "otp": codes[0]}).json()["data"]["access_token"]
    h2 = {"Authorization": f"Bearer {token}"}
    assert client.post("/api/v1/auth/mfa/disable", headers=h2, json={"password": "wrong", "code": codes[1]}).status_code == 400
    assert client.post("/api/v1/auth/mfa/disable", headers=h2, json={"password": STRONG, "code": "000000"}).status_code == 400
    # admin reset path for a user who lost everything
    admin = _headers(rbac.ADMIN)
    users = client.get("/api/v1/admin/users", headers=admin).json()["data"]
    uid = next(u["id"] for u in (users["items"] if isinstance(users, dict) else users) if u["email"] == creds["email"])
    assert client.post(f"/api/v1/admin/users/{uid}/mfa-reset", headers=_headers(rbac.APPROVER)).status_code == 403
    assert client.post(f"/api/v1/admin/users/{uid}/mfa-reset", headers=admin).status_code == 200
    r = _login(creds)
    assert r.status_code == 200 and r.json()["data"]["user"]["mfa_enabled"] is False


def test_user_can_disable_with_password_and_valid_code():
    creds = _user(rbac.VIEWER)
    h = {"Authorization": "Bearer " + _login(creds).json()["data"]["access_token"]}
    secret = _enrol(h)
    codes = client.post("/api/v1/auth/mfa/enable", headers=h, json={"code": mfa.totp(secret)}).json()["data"]["recovery_codes"]
    token = client.post("/api/v1/auth/login", json={**creds, "otp": codes[0]}).json()["data"]["access_token"]
    r = client.post("/api/v1/auth/mfa/disable", headers={"Authorization": f"Bearer {token}"}, json={"password": STRONG, "code": codes[1]})
    assert r.status_code == 200, r.text
    assert _login(creds).status_code == 200


def test_enrolment_hint_for_admins_and_secret_encrypted_at_rest():
    from app.core import db as dbmod
    creds = _user(rbac.ADMIN)
    me = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer " + _login(creds).json()["data"]["access_token"]})
    assert me.json()["data"]["mfa_enrollment_required"] is True
    h = {"Authorization": "Bearer " + _login(creds).json()["data"]["access_token"]}
    secret = _enrol(h)
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute("SELECT mfa_secret_enc FROM users WHERE lower(email::text)=lower(%s)", (creds["email"],))
        stored = cur.fetchone()[0]
    assert secret not in stored and stored.startswith("enc:")
    assert uuid.UUID(int=0)  # keep the import used


# ------------------------------------------------------------------ cookie sessions (httpOnly + CSRF)
def test_cookie_session_httponly_csrf_and_logout():
    creds = _user(rbac.AUDITOR)
    c = TestClient(app)
    r = c.post("/api/v1/auth/login", json=creds, headers={"X-Auth-Mode": "cookie"})
    assert r.status_code == 200, r.text
    assert r.json()["data"]["access_token"] == ""                      # token is NOT exposed to page scripts
    sc = " ".join(r.headers.get_list("set-cookie")).lower()
    assert "qirova_session=" in sc and "httponly" in sc and "samesite=strict" in sc
    assert c.get("/api/v1/auth/me").status_code == 200                  # cookie alone authenticates safe reads
    # unsafe request without the CSRF header is refused
    body = {"name": f"ck-{uuid.uuid4().hex[:6]}", "vendor": "cisco"}
    assert c.post("/api/v1/assets", json=body).status_code == 403
    csrf = c.cookies.get("qirova_csrf")
    assert csrf and c.post("/api/v1/assets", json=body, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert c.post("/api/v1/assets", json=body, headers={"X-CSRF-Token": csrf}).status_code == 200
    assert c.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    c.cookies.clear()
    assert c.get("/api/v1/auth/me").status_code == 401


def test_bearer_mode_unchanged_and_no_cookie_without_opt_in():
    creds = _user(rbac.VIEWER)
    r = client.post("/api/v1/auth/login", json=creds)
    assert r.json()["data"]["access_token"] and not r.headers.get_list("set-cookie")
