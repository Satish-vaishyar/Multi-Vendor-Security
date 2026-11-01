"""Single sign-on with OpenID Connect (authorization-code flow + PKCE), for Entra ID / Okta / Keycloak / Google Workspace.

Security properties (each has a test in tests/test_sso.py):
  * state + nonce + PKCE(S256); the transaction lives in a short-lived, signed, httpOnly cookie - nothing server-side
  * the ID token signature is verified against the IdP's JWKS; only asymmetric algorithms are accepted (never HS*/none)
  * iss, aud (and azp for multi-audience tokens), exp, nonce are all checked; unverified e-mails are refused
  * a local account is NEVER silently taken over: linking an existing e-mail needs OIDC_LINK_EXISTING_USERS=true
  * the role comes from the IdP groups on EVERY login (removing someone from the group demotes them and revokes
    their sessions); no mapped group and no OIDC_DEFAULT_ROLE means no access
  * the post-login redirect is the single configured frontend URL (no open redirect)
The HTTP layer (``_get`` / ``_post_form``) is injectable so the whole flow is tested against an in-process fake IdP.
"""
from __future__ import annotations
import base64
import hashlib
import json
import logging
import secrets
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode

import httpx
import jwt
from jwt import PyJWK

from app.core import config as cfg
from app.core import db as dbmod
from app.core import rbac

log = logging.getLogger("sih26155")

ALLOWED_ALGS = ["RS256", "RS384", "RS512", "PS256", "ES256", "ES384"]
TX_COOKIE = "qirova_sso_tx"
TX_TTL = 600


class SSOError(Exception):
    """Raised with a short machine reason; the HTTP layer maps it to a generic redirect (no detail to the browser)."""
    def __init__(self, reason: str, status: int = 400):
        super().__init__(reason)
        self.reason, self.status = reason, status


def enabled() -> bool:
    return bool(cfg.OIDC_ISSUER and cfg.OIDC_CLIENT_ID and cfg.OIDC_CLIENT_SECRET and cfg.OIDC_REDIRECT_URI)


# ------------------------------------------------------------------ transport (injectable)
def _get(url: str) -> dict:
    r = httpx.get(url, timeout=10.0, follow_redirects=False)
    if r.status_code != 200:
        raise SSOError("idp_unreachable", 502)
    return r.json()


def _post_form(url: str, data: Dict[str, str]) -> dict:
    r = httpx.post(url, data=data, timeout=10.0, follow_redirects=False,
                   headers={"Accept": "application/json"})
    if r.status_code != 200:
        raise SSOError("token_exchange_failed", 502)
    return r.json()


_cache: Dict[str, Tuple[float, Any]] = {}


def reset_cache() -> None:
    _cache.clear()


def discovery() -> dict:
    hit = _cache.get("disco")
    if hit and hit[0] > time.time():
        return hit[1]
    doc = _get(cfg.OIDC_ISSUER.rstrip("/") + "/.well-known/openid-configuration")
    if str(doc.get("issuer", "")).rstrip("/") != cfg.OIDC_ISSUER.rstrip("/"):
        raise SSOError("issuer_mismatch", 502)         # a discovery doc must describe the issuer we asked for
    for k in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not str(doc.get(k, "")).startswith("https://") and not _dev_http(doc.get(k, "")):
            raise SSOError("insecure_endpoint", 502)
    _cache["disco"] = (time.time() + 3600, doc)
    return doc


def _dev_http(url: str) -> bool:
    return cfg.ENV != "production" and str(url).startswith("http://")


def _jwks(force: bool = False) -> dict:
    hit = _cache.get("jwks")
    if hit and hit[0] > time.time() and not force:
        return hit[1]
    doc = _get(discovery()["jwks_uri"])
    _cache["jwks"] = (time.time() + 3600, doc)
    return doc


def _signing_key(token: str) -> Any:
    hdr = jwt.get_unverified_header(token)
    if hdr.get("alg") not in ALLOWED_ALGS:
        raise SSOError("bad_alg")
    for force in (False, True):                       # one refresh on an unknown kid (key rotation at the IdP)
        for k in _jwks(force).get("keys", []):
            if k.get("kid") == hdr.get("kid"):
                return PyJWK(k).key
    raise SSOError("unknown_kid")


# ------------------------------------------------------------------ login transaction
def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def begin() -> Tuple[str, str]:
    """Return (authorization URL, signed transaction cookie value)."""
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    tx = jwt.encode({"st": state, "n": nonce, "v": verifier, "exp": int(time.time()) + TX_TTL, "k": "sso-tx"},
                    cfg.JWT_SECRET, algorithm="HS256")
    q = urlencode({"response_type": "code", "client_id": cfg.OIDC_CLIENT_ID, "redirect_uri": cfg.OIDC_REDIRECT_URI,
                   "scope": cfg.OIDC_SCOPES, "state": state, "nonce": nonce,
                   "code_challenge": _b64(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"})
    return f"{discovery()['authorization_endpoint']}?{q}", tx


def _open_tx(tx: Optional[str], state: str) -> Dict[str, Any]:
    if not tx or not state:
        raise SSOError("missing_state")
    try:
        d = jwt.decode(tx, cfg.JWT_SECRET, algorithms=["HS256"], options={"require": ["exp"]})
    except Exception:
        raise SSOError("bad_state")
    if d.get("k") != "sso-tx" or not secrets.compare_digest(str(d.get("st", "")), state):
        raise SSOError("bad_state")
    return d


def complete(code: str, state: str, tx_cookie: Optional[str]) -> Dict[str, Any]:
    """Validate the callback and return the verified claims."""
    tx = _open_tx(tx_cookie, state)
    if not code:
        raise SSOError("missing_code")
    tok = _post_form(discovery()["token_endpoint"], {
        "grant_type": "authorization_code", "code": code, "redirect_uri": cfg.OIDC_REDIRECT_URI,
        "client_id": cfg.OIDC_CLIENT_ID, "client_secret": cfg.OIDC_CLIENT_SECRET, "code_verifier": tx["v"]})
    idt = tok.get("id_token")
    if not idt:
        raise SSOError("no_id_token")
    key = _signing_key(idt)
    try:
        claims = jwt.decode(idt, key, algorithms=ALLOWED_ALGS, audience=cfg.OIDC_CLIENT_ID,
                            issuer=discovery()["issuer"],
                            leeway=60, options={"require": ["exp", "iat", "iss", "aud", "sub"]})
    except Exception:
        raise SSOError("bad_id_token")
    aud = claims.get("aud")
    if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != cfg.OIDC_CLIENT_ID:
        raise SSOError("bad_azp")
    if not secrets.compare_digest(str(claims.get("nonce", "")), tx["n"]):
        raise SSOError("bad_nonce")
    return claims


# ------------------------------------------------------------------ claims -> user
def _role_map() -> Dict[str, str]:
    try:
        raw = json.loads(cfg.OIDC_ROLE_MAP or "{}")
    except ValueError:
        return {}
    return {str(k).lower(): str(v).upper() for k, v in raw.items() if str(v).upper() in rbac.ROLES}


def role_for(claims: Dict[str, Any]) -> Optional[str]:
    """Highest mapped role among the user's groups, else OIDC_DEFAULT_ROLE, else None (= no access)."""
    groups = claims.get(cfg.OIDC_GROUPS_CLAIM) or []
    if isinstance(groups, str):
        groups = [groups]
    m = _role_map()
    best: Optional[str] = None
    for g in groups:
        r = m.get(str(g).lower())
        if r and (best is None or rbac.ROLES.index(r) > rbac.ROLES.index(best)):
            best = r
    if best is None and cfg.OIDC_DEFAULT_ROLE.upper() in rbac.ROLES:
        best = cfg.OIDC_DEFAULT_ROLE.upper()
    return best


def resolve_user(claims: Dict[str, Any]) -> Dict[str, Any]:
    """Find / provision the local user for verified claims, sync its role, return it (security.make_token-ready)."""
    from app.core import security as sec
    email = str(claims.get("email") or claims.get("preferred_username") or "").strip().lower()
    if "@" not in email:
        raise SSOError("no_email")
    if claims.get("email_verified") is False or str(claims.get("email_verified", "")).lower() == "false":
        raise SSOError("email_not_verified", 403)
    domains = [d.strip().lower() for d in cfg.OIDC_ALLOWED_DOMAINS if d.strip()]
    if domains and email.rsplit("@", 1)[1] not in domains:
        raise SSOError("domain_not_allowed", 403)
    role = role_for(claims)
    if role is None:
        raise SSOError("no_role", 403)
    issuer, sub = cfg.OIDC_ISSUER.rstrip("/"), str(claims["sub"])
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("SELECT id FROM users WHERE sso_issuer=%s AND sso_subject=%s", (issuer, sub))
        row = cur.fetchone()
    user = sec._user_by_id(row[0]) if row else None
    if user is None:
        existing = sec._user_by_email(email)
        if existing is not None:
            if not cfg.OIDC_LINK_EXISTING_USERS:
                raise SSOError("account_exists", 403)
            user = existing
            with dbmod.get_conn() as conn:
                conn.cursor().execute("UPDATE users SET sso_issuer=%s, sso_subject=%s, auth_provider='oidc' WHERE id=%s",  # type: ignore[attr-defined]
                                      (issuer, sub, user["id"]))
        else:
            if not cfg.OIDC_AUTO_PROVISION:
                raise SSOError("not_provisioned", 403)
            name = str(claims.get("name") or email.split("@")[0])[:120]
            user = sec.create_user(email, name, secrets.token_urlsafe(32), role, org_id=cfg.OIDC_ORG_ID or cfg.DEFAULT_ORG_ID,
                                   enforce_policy=False)
            with dbmod.get_conn() as conn:
                conn.cursor().execute("UPDATE users SET sso_issuer=%s, sso_subject=%s, auth_provider='oidc' WHERE id=%s",  # type: ignore[attr-defined]
                                      (issuer, sub, user["id"]))
    if user.get("disabled"):
        raise SSOError("disabled", 403)
    if user["role"] != role:
        with dbmod.get_conn() as conn:
            conn.cursor().execute("UPDATE users SET role=%s, token_version=token_version+1 WHERE id=%s",  # type: ignore[attr-defined]
                                  (role, user["id"]))
        user = sec._user_by_id(user["id"]) or user
    return user


def public_config() -> Dict[str, Any]:
    return {"enabled": enabled(), "provider": cfg.OIDC_PROVIDER_NAME if enabled() else "",
            "password_login": not (enabled() and cfg.SSO_ONLY)}

