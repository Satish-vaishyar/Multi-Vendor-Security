"""Envelope encryption through Vault Transit / AWS KMS, exercised against in-process fake key services."""
import base64
import datetime as dt
import json

import pytest

from app import cli
from app.core import config as cfg
from app.core import crypto, keyprovider


class FakeKeyService:
    """Reversible 'wrapping' that records what it was asked, so we can assert no plain key is ever sent in clear."""
    def __init__(self):
        self.calls = []

    def __call__(self, url, headers, body):
        req = json.loads(body)
        self.calls.append((url, dict(headers), req))
        if "/transit/encrypt/" in url:
            return {"data": {"ciphertext": "vault:v1:" + base64.b64encode(req["plaintext"].encode()[::-1]).decode()}}
        if "/transit/decrypt/" in url:
            raw = base64.b64decode(req["ciphertext"][len("vault:v1:"):])[::-1].decode()
            return {"data": {"plaintext": raw}}
        target = headers["x-amz-target"]
        if target.endswith("Encrypt"):
            return {"CiphertextBlob": "kms-" + base64.b64encode(req["Plaintext"].encode()[::-1]).decode()}
        return {"Plaintext": base64.b64decode(req["CiphertextBlob"][4:])[::-1].decode()}


@pytest.fixture
def svc(monkeypatch):
    s = FakeKeyService()
    monkeypatch.setattr(keyprovider, "_post", s)
    yield s
    crypto.reset()


def _vault(monkeypatch):
    for k, v in (("KEY_PROVIDER", "vault"), ("VAULT_ADDR", "https://vault.example:8200"), ("VAULT_TOKEN", "s.tok"),
                 ("VAULT_TRANSIT_KEY", "auditor"), ("VAULT_NAMESPACE", "ns1")):
        monkeypatch.setattr(cfg, k, v)


def _aws(monkeypatch):
    for k, v in (("KEY_PROVIDER", "aws-kms"), ("AWS_REGION", "ap-south-1"), ("KMS_KEY_ID", "alias/auditor"),
                 ("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE"), ("AWS_SECRET_ACCESS_KEY", "secretexample")):
        monkeypatch.setattr(cfg, k, v)


@pytest.mark.parametrize("setup", [_vault, _aws])
def test_wrapped_keys_round_trip_through_crypto(monkeypatch, svc, setup):
    setup(monkeypatch)
    wrapped = keyprovider.wrap(key := crypto.generate_key())
    assert key not in wrapped                                       # the plain key is not in the stored form
    monkeypatch.setattr(cfg, "DATA_ENCRYPTION_KEYS", [])
    monkeypatch.setattr(cfg, "DATA_ENCRYPTION_KEYS_WRAPPED", [wrapped])
    crypto.reset()
    token = crypto.encrypt("hostname R1")
    assert crypto.is_encrypted(token) and crypto.decrypt(token) == "hostname R1"
    # a second process with the same wrapped key can read what the first wrote
    crypto.reset()
    assert crypto.decrypt(token) == "hostname R1"


def test_vault_request_shape(monkeypatch, svc):
    _vault(monkeypatch)
    keyprovider.wrap("k" * 44)
    url, headers, req = svc.calls[0]
    assert url == "https://vault.example:8200/v1/transit/encrypt/auditor"
    assert headers["X-Vault-Token"] == "s.tok" and headers["X-Vault-Namespace"] == "ns1"
    assert base64.b64decode(req["plaintext"]).decode() == "k" * 44        # base64, as the Transit API requires


def test_aws_request_is_signed_and_hides_the_secret(monkeypatch, svc):
    _aws(monkeypatch)
    keyprovider.wrap("k" * 44)
    url, headers, req = svc.calls[0]
    assert url == "https://kms.ap-south-1.amazonaws.com/" and req["KeyId"] == "alias/auditor"
    auth = headers["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") and "/ap-south-1/kms/aws4_request" in auth
    assert "SignedHeaders=content-type;host;x-amz-date;x-amz-target" in auth
    assert "secretexample" not in json.dumps(headers)


def test_sigv4_signing_key_matches_the_published_aws_vector():
    # https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
    k = keyprovider.sigv4_signing_key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20120215", "us-east-1", "iam")
    assert k.hex() == "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"


def test_sigv4_signature_is_deterministic_and_session_token_is_signed(monkeypatch):
    _aws(monkeypatch)
    monkeypatch.setattr(cfg, "AWS_SESSION_TOKEN", "tok")
    now = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)
    a = keyprovider.sigv4_headers("kms.ap-south-1.amazonaws.com", "ap-south-1", "TrentService.Decrypt", b"{}", now)
    b = keyprovider.sigv4_headers("kms.ap-south-1.amazonaws.com", "ap-south-1", "TrentService.Decrypt", b"{}", now)
    c = keyprovider.sigv4_headers("kms.ap-south-1.amazonaws.com", "ap-south-1", "TrentService.Decrypt", b"{ }", now)
    assert a == b and a["Authorization"] != c["Authorization"]
    assert a["x-amz-security-token"] == "tok" and "x-amz-security-token" in a["Authorization"]


def test_missing_provider_settings_fail_loudly(monkeypatch, svc):
    monkeypatch.setattr(cfg, "KEY_PROVIDER", "vault")
    for k in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_TRANSIT_KEY"):
        monkeypatch.setattr(cfg, k, "")
    with pytest.raises(keyprovider.KeyProviderError):
        keyprovider.wrap("x")
    monkeypatch.setattr(cfg, "KEY_PROVIDER", "aws-kms")
    monkeypatch.setattr(cfg, "AWS_ACCESS_KEY_ID", "")
    monkeypatch.setattr(cfg, "AWS_REGION", "ap-south-1")
    monkeypatch.setattr(cfg, "KMS_KEY_ID", "k")
    with pytest.raises(keyprovider.KeyProviderError):
        keyprovider.wrap("x")
    monkeypatch.setattr(cfg, "KEY_PROVIDER", "env")
    with pytest.raises(keyprovider.KeyProviderError):
        keyprovider.wrap("x")
    with pytest.raises(keyprovider.KeyProviderError):
        keyprovider.unwrap("x")
    monkeypatch.setattr(cfg, "KEY_PROVIDER", "vault")
    monkeypatch.setattr(cfg, "DATA_ENCRYPTION_KEYS_WRAPPED", [])
    with pytest.raises(keyprovider.KeyProviderError):
        keyprovider.load_keys()


def test_production_validation_rules(monkeypatch):
    assert keyprovider.problems() == [] or "DATA_ENCRYPTION_KEYS" in keyprovider.problems()[0]
    monkeypatch.setattr(cfg, "KEY_PROVIDER", "rot13")
    assert "KEY_PROVIDER must be" in keyprovider.problems()[0]
    _vault(monkeypatch)
    monkeypatch.setattr(cfg, "DATA_ENCRYPTION_KEYS", ["plain"])
    monkeypatch.setattr(cfg, "DATA_ENCRYPTION_KEYS_WRAPPED", [])
    msgs = " | ".join(keyprovider.problems())
    assert "WRAPPED must be set" in msgs and "plain keys) must be empty" in msgs
    monkeypatch.setattr(cfg, "DATA_ENCRYPTION_KEYS", [])
    monkeypatch.setattr(cfg, "DATA_ENCRYPTION_KEYS_WRAPPED", ["w"])
    assert keyprovider.problems() == []
    _aws(monkeypatch)
    monkeypatch.setattr(cfg, "KMS_KEY_ID", "")
    assert any("KMS_KEY_ID" in p for p in keyprovider.problems())


def test_transport_error_never_leaks_the_response_body(monkeypatch):
    class R:
        status_code = 403
        text = "AccessDenied for key arn:aws:kms:secret"
        def json(self): return {}
    monkeypatch.setattr(keyprovider.httpx, "post", lambda *a, **k: R())
    with pytest.raises(keyprovider.KeyProviderError) as e:
        keyprovider._post("https://x", {}, b"{}")
    assert "403" in str(e.value) and "arn:" not in str(e.value)
    class OK(R):
        status_code = 200
        def json(self): return {"a": 1}
    monkeypatch.setattr(keyprovider.httpx, "post", lambda *a, **k: OK())
    assert keyprovider._post("https://x", {}, b"{}") == {"a": 1}


def test_cli_kms_wrap(monkeypatch, svc, capsys):
    _vault(monkeypatch)
    assert cli.main(["kms-wrap"]) == 0
    assert capsys.readouterr().out.strip().startswith("vault:v1:")
    monkeypatch.setattr(cfg, "KEY_PROVIDER", "env")
    assert cli.main(["kms-wrap"]) == 1
    assert "KEY_PROVIDER" in capsys.readouterr().out
