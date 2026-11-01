"""Envelope encryption: the data-encryption keys (DEKs) are stored WRAPPED by an external key service and unwrapped
into process memory at start-up. The master key never leaves the key service, so a stolen database dump AND a stolen
environment file together still cannot decrypt anything without access to the KMS/Vault.

Providers (KEY_PROVIDER):
  env      DATA_ENCRYPTION_KEYS holds the plain Fernet keys (default; fine for small / self-hosted installs)
  vault    HashiCorp Vault Transit engine   (VAULT_ADDR, VAULT_TOKEN, VAULT_TRANSIT_KEY[, VAULT_NAMESPACE])
  aws-kms  AWS KMS Encrypt/Decrypt          (AWS_REGION, KMS_KEY_ID, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY[, AWS_SESSION_TOKEN])

With vault / aws-kms, DATA_ENCRYPTION_KEYS_WRAPPED carries the wrapped keys (newest first). Create one with
`python -m app.cli kms-wrap` (prints a wrapped key; the plain key is never shown). Rotation of the MASTER key is done in
the key service (Vault `rotate` + `rewrap`, KMS automatic rotation); rotation of a DEK is "wrap a new one, prepend it,
run `reencrypt`".

Nothing here talks to a real key service in the test-suite: the HTTP transport is injectable (``_post``).
"""
from __future__ import annotations
import base64
import datetime as _dt
import hashlib
import hmac
import json
import logging
from typing import Dict, List
from urllib.parse import urlparse

import httpx

from app.core import config as cfg

log = logging.getLogger("sih26155")


class KeyProviderError(RuntimeError):
    pass


def _post(url: str, headers: Dict[str, str], body: bytes) -> dict:
    r = httpx.post(url, headers=headers, content=body, timeout=10.0)
    if r.status_code >= 300:
        # never echo the response body: it can contain request ids / key ids, and never the key material
        raise KeyProviderError(f"key service returned HTTP {r.status_code}")
    return r.json()


# ------------------------------------------------------------------ Vault transit
def _vault(op: str, payload: dict) -> dict:
    if not (cfg.VAULT_ADDR and cfg.VAULT_TOKEN and cfg.VAULT_TRANSIT_KEY):
        raise KeyProviderError("VAULT_ADDR, VAULT_TOKEN and VAULT_TRANSIT_KEY are required for KEY_PROVIDER=vault")
    headers = {"X-Vault-Token": cfg.VAULT_TOKEN, "Content-Type": "application/json"}
    if cfg.VAULT_NAMESPACE:
        headers["X-Vault-Namespace"] = cfg.VAULT_NAMESPACE
    url = f"{cfg.VAULT_ADDR.rstrip('/')}/v1/transit/{op}/{cfg.VAULT_TRANSIT_KEY}"
    return _post(url, headers, json.dumps(payload).encode())["data"]


# ------------------------------------------------------------------ AWS SigV4 (stdlib only)
def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sigv4_signing_key(secret: str, date: str, region: str, service: str) -> bytes:
    k = _hmac(("AWS4" + secret).encode(), date)
    return _hmac(_hmac(_hmac(k, region), service), "aws4_request")


def sigv4_headers(host: str, region: str, target: str, body: bytes, now: _dt.datetime | None = None) -> Dict[str, str]:
    if not (cfg.AWS_ACCESS_KEY_ID and cfg.AWS_SECRET_ACCESS_KEY):
        raise KeyProviderError("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required for KEY_PROVIDER=aws-kms")
    now = now or _dt.datetime.now(_dt.timezone.utc)
    amz, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    hdrs = {"content-type": "application/x-amz-json-1.1", "host": host, "x-amz-date": amz, "x-amz-target": target}
    if cfg.AWS_SESSION_TOKEN:
        hdrs["x-amz-security-token"] = cfg.AWS_SESSION_TOKEN
    names = sorted(hdrs)
    canonical = "POST\n/\n\n" + "".join(f"{n}:{hdrs[n]}\n" for n in names) + "\n" + ";".join(names) + "\n" + hashlib.sha256(body).hexdigest()
    scope = f"{date}/{region}/kms/aws4_request"
    to_sign = f"AWS4-HMAC-SHA256\n{amz}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}"
    sig = hmac.new(sigv4_signing_key(cfg.AWS_SECRET_ACCESS_KEY, date, region, "kms"), to_sign.encode(), hashlib.sha256).hexdigest()
    out = {n: v for n, v in hdrs.items() if n != "host"}
    out["Authorization"] = (f"AWS4-HMAC-SHA256 Credential={cfg.AWS_ACCESS_KEY_ID}/{scope}, "
                            f"SignedHeaders={';'.join(names)}, Signature={sig}")
    return out


def _aws(op: str, payload: dict) -> dict:
    if not (cfg.AWS_REGION and cfg.KMS_KEY_ID):
        raise KeyProviderError("AWS_REGION and KMS_KEY_ID are required for KEY_PROVIDER=aws-kms")
    url = f"https://kms.{cfg.AWS_REGION}.amazonaws.com/"
    body = json.dumps(payload).encode()
    headers = sigv4_headers(urlparse(url).netloc, cfg.AWS_REGION, f"TrentService.{op}", body)
    return _post(url, headers, body)


# ------------------------------------------------------------------ public API
def wrap(plain_key: str) -> str:
    """Wrap a plain Fernet key with the configured provider."""
    raw = base64.b64encode(plain_key.encode()).decode()
    if cfg.KEY_PROVIDER == "vault":
        return _vault("encrypt", {"plaintext": raw})["ciphertext"]
    if cfg.KEY_PROVIDER == "aws-kms":
        return _aws("Encrypt", {"KeyId": cfg.KMS_KEY_ID, "Plaintext": raw})["CiphertextBlob"]
    raise KeyProviderError("KEY_PROVIDER must be vault or aws-kms to wrap keys")


def unwrap(blob: str) -> str:
    if cfg.KEY_PROVIDER == "vault":
        raw = _vault("decrypt", {"ciphertext": blob})["plaintext"]
    elif cfg.KEY_PROVIDER == "aws-kms":
        raw = _aws("Decrypt", {"KeyId": cfg.KMS_KEY_ID, "CiphertextBlob": blob})["Plaintext"]
    else:
        raise KeyProviderError("KEY_PROVIDER must be vault or aws-kms to unwrap keys")
    return base64.b64decode(raw).decode()


def load_keys() -> List[str]:
    """Plain Fernet keys, newest first, from whichever provider is configured."""
    if cfg.KEY_PROVIDER == "env":
        return list(cfg.DATA_ENCRYPTION_KEYS)
    if not cfg.DATA_ENCRYPTION_KEYS_WRAPPED:
        raise KeyProviderError("DATA_ENCRYPTION_KEYS_WRAPPED is empty (create one with `python -m app.cli kms-wrap`)")
    keys = [unwrap(b) for b in cfg.DATA_ENCRYPTION_KEYS_WRAPPED]
    log.info("unwrapped %d data-encryption key(s) via %s", len(keys), cfg.KEY_PROVIDER)
    return keys


def problems() -> List[str]:
    """Configuration problems for validate_production()."""
    if cfg.KEY_PROVIDER == "env":
        return [] if cfg.DATA_ENCRYPTION_KEYS else ["DATA_ENCRYPTION_KEYS must be set (Fernet key; see docs/SECURITY.md)"]
    out: List[str] = []
    if cfg.KEY_PROVIDER not in ("vault", "aws-kms"):
        return [f"KEY_PROVIDER must be env, vault or aws-kms (got {cfg.KEY_PROVIDER!r})"]
    if not cfg.DATA_ENCRYPTION_KEYS_WRAPPED:
        out.append("DATA_ENCRYPTION_KEYS_WRAPPED must be set when KEY_PROVIDER is not env")
    if cfg.DATA_ENCRYPTION_KEYS:
        out.append("DATA_ENCRYPTION_KEYS (plain keys) must be empty when a KMS provider is used")
    need = (("VAULT_ADDR", cfg.VAULT_ADDR), ("VAULT_TOKEN", cfg.VAULT_TOKEN), ("VAULT_TRANSIT_KEY", cfg.VAULT_TRANSIT_KEY)) \
        if cfg.KEY_PROVIDER == "vault" else \
        (("AWS_REGION", cfg.AWS_REGION), ("KMS_KEY_ID", cfg.KMS_KEY_ID),
         ("AWS_ACCESS_KEY_ID", cfg.AWS_ACCESS_KEY_ID), ("AWS_SECRET_ACCESS_KEY", cfg.AWS_SECRET_ACCESS_KEY))
    out += [f"{n} must be set for KEY_PROVIDER={cfg.KEY_PROVIDER}" for n, v in need if not v]
    return out
