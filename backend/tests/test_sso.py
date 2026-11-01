"""OIDC single sign-on against an in-process fake IdP (real RSA keys, real signed ID tokens)."""
import base64
import hashlib
import json
import time
import uuid
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from app.core import config as cfg
from app.core import db as dbmod
from app.core import oidc
from app.core import security as sec
from app.main import app

ISS = "https://idp.example.com/realms/corp"
CID = "auditor"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(key, kid):
    d = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    d.update(kid=kid, use="sig", alg="RS256")
    return d


class FakeIdP:
    def __init__(self):
        self.claims = {}                 # overrides merged into the ID token
        self.sign_key, self.kid, self.alg = KEY, "k1", "RS256"
        self.jwks = {"keys": [_jwk(KEY, "k1")]}
        self.issuer_in_doc = ISS
        self.token_status = 200
        self.exchanged = []
        self.last_nonce = ""

    def get(self, url):
        if url.endswith("/.well-known/openid-configuration"):
            return {"issuer": self.issuer_in_doc, "authorization_endpoint": ISS + "/auth",
                    "token_endpoint": ISS + "/token", "jwks_uri": ISS + "/certs"}
        if url == ISS + "/certs":
            return self.jwks
        raise AssertionError(url)

    def post_form(self, url, data):
        self.exchanged.append(dict(data))
        if self.token_status != 200:
            raise oidc.SSOError("token_exchange_failed", 502)
        now = int(time.time())
        c = {"iss": ISS, "aud": CID, "sub": "sub-" + uuid.uuid4().hex[:8], "iat": now, "exp": now + 300,
             "nonce": self.last_nonce, "email": f"sso-{uuid.uuid4().hex[:8]}@corp.example",
             "email_verified": True, "name": "Sam SSO", "groups": ["auditors"]}
        c.update(self.claims)
        key = self.sign_key if self.alg != "HS256" else cfg.OIDC_CLIENT_SECRET
        return {"id_token": jwt.encode({k: v for k, v in c.items() if v is not None}, key, algorithm=self.alg,
                                       headers={"kid": self.kid}), "access_token": "x"}


@pytest.fixture
def idp(monkeypatch):
    f = FakeIdP()
    monkeypatch.setattr(oidc, "_get", f.get)
    monkeypatch.setattr(oidc, "_post_form", f.post_form)
    for k, v in (("OIDC_ISSUER", ISS), ("OIDC_CLIENT_ID", CID), ("OIDC_CLIENT_SECRET", "s3cret-s3cret-s3cret"),
                 ("OIDC_REDIRECT_URI", "https://api.example.com/api/v1/auth/sso/callback"),
                 ("OIDC_ROLE_MAP", json.dumps({"admins": "ADMIN", "approvers": "APPROVER", "auditors": "AUDITOR"})),
                 ("OIDC_DEFAULT_ROLE", ""), ("OIDC_ALLOWED_DOMAINS", []), ("OIDC_AUTO_PROVISION", True),
                 ("OIDC_LINK_EXISTING_USERS", False), ("OIDC_FRONTEND_URL", "https://app.example.com"),
                 ("SSO_ONLY", False), ("OIDC_GROUPS_CLAIM", "groups")):
        monkeypatch.setattr(cfg, k, v)
    oidc.reset_cache()
    yield f
    oidc.reset_cache()


def _login(c, idp_):
    r = c.get("/api/v1/auth/sso/login", follow_redirects=False)
    assert r.status_code == 303
    q = parse_qs(urlparse(r.headers["location"]).query)
    idp_.last_nonce = q["nonce"][0]
    return r, q


def _run(c, idp_, state_override=None):
    _, q = _login(c, idp_)
    return c.get("/api/v1/auth/sso/callback", params={"code": "abc", "state": state_override or q["state"][0]},
                 follow_redirects=False), q


def _fresh():
    return TestClient(app)


def _ok(r):
    return r.status_code == 303 and r.headers["location"] == "https://app.example.com/sso/complete"


def _refused(r):
    return r.status_code == 303 and r.headers["location"] == "https://app.example.com/login?sso_error=1"


def _role_of(email):
    return sec._user_by_email(email)["role"]


# ---------------------------------------------------------------- happy path
def test_full_login_provisions_user_and_sets_an_httponly_session(idp):
    c = _fresh()
    r, q = _run(c, idp)
    assert q["code_challenge_method"] == ["S256"] and q["client_id"] == [CID] and q["scope"] == ["openid email profile"]
    assert _ok(r)
    cookie = r.headers.get_list("set-cookie")
    sess = [h for h in cookie if h.startswith(cfg.SESSION_COOKIE + "=")][0]
    assert "HttpOnly" in sess and "SameSite=strict" in sess
    me = c.get("/api/v1/auth/me")                      # the cookie alone authenticates
    assert me.status_code == 200 and me.json()["data"]["role"] == "AUDITOR"
    email = me.json()["data"]["email"]
    assert sec._user_by_email(email)["name"] == "Sam SSO"
    # PKCE: the verifier sent to the token endpoint matches the challenge sent to the browser
    v = idp.exchanged[-1]["code_verifier"]
    assert q["code_challenge"][0] == base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
    assert idp.exchanged[-1]["client_secret"] == "s3cret-s3cret-s3cret" and idp.exchanged[-1]["code"] == "abc"


def test_highest_mapped_group_wins_and_default_role_applies(idp, monkeypatch):
    idp.claims = {"groups": ["auditors", "admins", "unmapped"]}
    r, _ = _run(_fresh(), idp)
    assert _ok(r)
    idp.claims = {"groups": ["nobody"]}
    assert _refused(_run(_fresh(), idp)[0])
    monkeypatch.setattr(cfg, "OIDC_DEFAULT_ROLE", "viewer")
    mail = f"def-{uuid.uuid4().hex[:6]}@corp.example"
    idp.claims = {"groups": ["nobody"], "email": mail}
    assert _ok(_run(_fresh(), idp)[0]) and _role_of(mail) == "VIEWER"
    idp.claims = {"groups": "admins", "email": f"s-{uuid.uuid4().hex[:6]}@corp.example"}      # a single string claim
    assert _ok(_run(_fresh(), idp)[0])


def test_role_is_resynced_every_login_and_demotion_revokes_sessions(idp):
    mail, sub = f"re-{uuid.uuid4().hex[:6]}@corp.example", "sub-fixed-1"
    idp.claims = {"email": mail, "sub": sub, "groups": ["admins"]}
    c = _fresh()
    assert _ok(_run(c, idp)[0]) and _role_of(mail) == "ADMIN"
    assert c.get("/api/v1/auth/me").status_code == 200
    idp.claims = {"email": mail, "sub": sub, "groups": ["auditors"]}
    assert _ok(_run(_fresh(), idp)[0]) and _role_of(mail) == "AUDITOR"
    assert c.get("/api/v1/auth/me").status_code == 401         # the old ADMIN session died with the demotion


# ---------------------------------------------------------------- hostile / broken callbacks
@pytest.mark.parametrize("claims", [
    {"aud": "someone-else"},
    {"iss": "https://evil.example/realms/corp"},
    {"exp": int(time.time()) - 3600},
    {"nonce": "replayed-nonce"},
    {"aud": [CID, "other"], "azp": "other"},
    {"email_verified": False},
    {"email": "not-an-email", "preferred_username": None},
])
def test_invalid_id_tokens_are_refused(idp, claims):
    idp.claims = claims
    c = _fresh()
    r, _ = _run(c, idp)
    assert _refused(r)
    assert c.get("/api/v1/auth/me").status_code == 401


def test_nonce_is_bound_to_the_login_transaction(idp):
    c = _fresh()
    _, q = _login(c, idp)
    idp.last_nonce = "attacker-supplied"
    r = c.get("/api/v1/auth/sso/callback", params={"code": "abc", "state": q["state"][0]}, follow_redirects=False)
    assert _refused(r)


def test_token_signed_with_the_wrong_key_or_unknown_kid_is_refused(idp):
    idp.sign_key = OTHER_KEY
    assert _refused(_run(_fresh(), idp)[0])
    idp.sign_key, idp.kid = KEY, "unknown"
    assert _refused(_run(_fresh(), idp)[0])


def test_hs256_algorithm_confusion_and_none_are_refused(idp, monkeypatch):
    idp.alg = "HS256"                                   # signed with the client secret as an HMAC key
    assert _refused(_run(_fresh(), idp)[0])
    c = _fresh()
    _, q = _login(c, idp)
    unsigned = jwt.encode({"iss": ISS, "aud": CID, "sub": "x", "exp": int(time.time()) + 99, "iat": int(time.time()),
                           "nonce": q["nonce"][0], "email": "a@corp.example", "groups": ["admins"]}, None, algorithm="none")
    monkeypatch.setattr(oidc, "_post_form", lambda _url, _data: {"id_token": unsigned})
    assert _refused(c.get("/api/v1/auth/sso/callback", params={"code": "abc", "state": q["state"][0]}, follow_redirects=False))


def test_key_rotation_refreshes_the_jwks_once(idp):
    assert _ok(_run(_fresh(), idp)[0])
    new = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    idp.sign_key, idp.kid = new, "k2"
    idp.jwks = {"keys": [_jwk(KEY, "k1"), _jwk(new, "k2")]}
    assert _ok(_run(_fresh(), idp)[0])                  # kid k2 unknown to the cache -> one refresh -> accepted


def test_state_cookie_tampering_missing_state_and_idp_errors(idp):
    c = _fresh()
    _, q = _login(c, idp)
    assert _refused(c.get("/api/v1/auth/sso/callback", params={"code": "abc", "state": "other"}, follow_redirects=False))
    assert _refused(_fresh().get("/api/v1/auth/sso/callback", params={"code": "abc", "state": q["state"][0]}, follow_redirects=False))
    c2 = _fresh()
    _login(c2, idp)
    assert _refused(c2.get("/api/v1/auth/sso/callback", params={"error": "access_denied"}, follow_redirects=False))
    c3 = _fresh()
    _, q3 = _login(c3, idp)
    assert _refused(c3.get("/api/v1/auth/sso/callback", params={"state": q3["state"][0]}, follow_redirects=False))
    forged = jwt.encode({"st": "s", "n": "n", "v": "v", "k": "sso-tx", "exp": int(time.time()) + 99}, "wrong-secret", algorithm="HS256")
    c4 = _fresh()
    c4.cookies.set(oidc.TX_COOKIE, forged, path="/api/v1/auth/sso")
    assert _refused(c4.get("/api/v1/auth/sso/callback", params={"code": "abc", "state": "s"}, follow_redirects=False))


def test_token_endpoint_failure_and_discovery_issuer_mismatch(idp):
    idp.token_status = 502
    assert _refused(_run(_fresh(), idp)[0])
    idp.token_status = 200
    idp.issuer_in_doc = "https://evil.example"
    oidc.reset_cache()
    assert _refused(_fresh().get("/api/v1/auth/sso/login", follow_redirects=False))


# ---------------------------------------------------------------- account policy
def test_existing_local_account_is_never_silently_taken_over(idp, monkeypatch):
    mail = f"local-{uuid.uuid4().hex[:6]}@corp.example"
    sec.create_user(mail, "Local", "Sup3r-Secret-Pass!", "VIEWER")
    idp.claims = {"email": mail, "groups": ["admins"]}
    assert _refused(_run(_fresh(), idp)[0]) and _role_of(mail) == "VIEWER"
    monkeypatch.setattr(cfg, "OIDC_LINK_EXISTING_USERS", True)
    assert _ok(_run(_fresh(), idp)[0]) and _role_of(mail) == "ADMIN"


def test_domain_allow_list_provisioning_switch_and_disabled_users(idp, monkeypatch):
    monkeypatch.setattr(cfg, "OIDC_ALLOWED_DOMAINS", ["corp.example"])
    idp.claims = {"email": "x@evil.example"}
    assert _refused(_run(_fresh(), idp)[0])
    monkeypatch.setattr(cfg, "OIDC_ALLOWED_DOMAINS", [])
    monkeypatch.setattr(cfg, "OIDC_AUTO_PROVISION", False)
    idp.claims = {"email": f"new-{uuid.uuid4().hex[:6]}@corp.example"}
    assert _refused(_run(_fresh(), idp)[0])
    monkeypatch.setattr(cfg, "OIDC_AUTO_PROVISION", True)
    mail, sub = f"dis-{uuid.uuid4().hex[:6]}@corp.example", "sub-dis"
    idp.claims = {"email": mail, "sub": sub}
    assert _ok(_run(_fresh(), idp)[0])
    with dbmod.get_conn() as conn:
        conn.cursor().execute("UPDATE users SET disabled=true WHERE lower(email::text)=lower(%s)", (mail,))
    assert _refused(_run(_fresh(), idp)[0])


def test_sso_users_cannot_use_password_login_and_sso_only_mode(idp, monkeypatch):
    mail = f"pw-{uuid.uuid4().hex[:6]}@corp.example"
    idp.claims = {"email": mail}
    assert _ok(_run(_fresh(), idp)[0])
    c = _fresh()
    assert c.post("/api/v1/auth/login", json={"email": mail, "password": "guess-guess-guess"}).status_code == 401
    # SSO_ONLY: a normal local user is refused even with the right password; an ADMIN keeps break-glass access
    monkeypatch.setattr(cfg, "SSO_ONLY", True)
    u = f"loc-{uuid.uuid4().hex[:6]}@corp.example"
    sec.create_user(u, "L", "Sup3r-Secret-Pass!", "AUDITOR")
    r = c.post("/api/v1/auth/login", json={"email": u, "password": "Sup3r-Secret-Pass!"})
    assert r.status_code == 403 and "single sign-on" in r.text
    a = f"adm-{uuid.uuid4().hex[:6]}@corp.example"
    sec.create_user(a, "A", "Sup3r-Secret-Pass!", "ADMIN")
    assert c.post("/api/v1/auth/login", json={"email": a, "password": "Sup3r-Secret-Pass!"}).status_code == 200


def test_config_endpoint_and_disabled_mode(idp, monkeypatch):
    c = _fresh()
    d = c.get("/api/v1/auth/sso/config").json()["data"]
    assert d["enabled"] is True and d["password_login"] is True
    monkeypatch.setattr(cfg, "SSO_ONLY", True)
    assert c.get("/api/v1/auth/sso/config").json()["data"]["password_login"] is False
    monkeypatch.setattr(cfg, "OIDC_ISSUER", "")
    assert c.get("/api/v1/auth/sso/config").json()["data"] == {"enabled": False, "provider": "", "password_login": True}
    assert c.get("/api/v1/auth/sso/login", follow_redirects=False).status_code == 404
    assert c.get("/api/v1/auth/sso/callback", follow_redirects=False).status_code == 404


def test_login_endpoint_is_ip_throttled_and_internal_errors_do_not_leak(idp, monkeypatch):
    with monkeypatch.context() as m:
        m.setattr(sec, "_ip_throttled", lambda _ip: True)
        assert _fresh().get("/api/v1/auth/sso/login", follow_redirects=False).status_code == 429
    c = _fresh()
    _, q = _login(c, idp)
    monkeypatch.setattr(oidc, "resolve_user", lambda claims: 1 / 0)
    r = c.get("/api/v1/auth/sso/callback", params={"code": "abc", "state": q["state"][0]}, follow_redirects=False)
    assert r.status_code == 303 and "division" not in r.text and "sso_error=1" in r.headers["location"]


def test_invalid_role_map_is_ignored(idp, monkeypatch):
    monkeypatch.setattr(cfg, "OIDC_ROLE_MAP", "{not json")
    assert _refused(_run(_fresh(), idp)[0])
    monkeypatch.setattr(cfg, "OIDC_ROLE_MAP", json.dumps({"auditors": "GOD"}))
    assert _refused(_run(_fresh(), idp)[0])

