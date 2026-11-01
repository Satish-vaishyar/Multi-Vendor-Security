"""Field-level encryption at rest (Fernet = AES-128-CBC + HMAC-SHA256).

Sensitive columns (device configs, raw unknown lines) are encrypted in the
application BEFORE they reach the database, so the managed DB provider (and
anyone holding a DB dump) never sees plaintext. Keys come from
DATA_ENCRYPTION_KEYS (comma separated, newest first = rotation: prepend a new
key, old rows still decrypt; run `python -m app.cli reencrypt` to roll them).

Ciphertext format:  enc:v1:<fernet-token>   Plaintext (legacy rows) passes through.
"""
from __future__ import annotations
import logging
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.core import config as cfg

log = logging.getLogger("sih26155")

PREFIX = "enc:v1:"
# Development-only fallback so a fresh checkout works. NEVER used in production
# (validate_production() requires DATA_ENCRYPTION_KEYS) and loudly logged.
_DEV_KEY = "ZGV2LW9ubHktSU5TRUNVUkUta2V5LTAxMjM0NTY3ODk="

_fernet: Optional[MultiFernet] = None
_warned = False


def generate_key() -> str:
    return Fernet.generate_key().decode()


def _get() -> MultiFernet:
    global _fernet, _warned
    if _fernet is None:
        from app.core import keyprovider
        keys = keyprovider.load_keys()
        if not keys:
            if cfg.ENV == "production":
                raise RuntimeError("DATA_ENCRYPTION_KEYS is required in production")
            if not _warned:
                log.warning("DATA_ENCRYPTION_KEYS not set: using the INSECURE development key. "
                            "Set a real key before storing real configurations.")
                _warned = True
            keys = [_DEV_KEY]
        _fernet = MultiFernet([Fernet(k.encode()) for k in keys])
    return _fernet


def reset() -> None:
    """Drop the cached key ring (tests / key rotation)."""
    global _fernet
    _fernet = None


def is_encrypted(value: object) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def encrypt(value: Optional[str]) -> Optional[str]:
    if value is None or is_encrypted(value):
        return value
    return PREFIX + _get().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt(value: Optional[str]) -> Optional[str]:
    if not is_encrypted(value):
        return value  # legacy plaintext row
    try:
        return _get().decrypt(value[len(PREFIX):].encode("ascii")).decode("utf-8")  # type: ignore[index]
    except InvalidToken as e:
        raise RuntimeError("cannot decrypt stored value: wrong or missing DATA_ENCRYPTION_KEYS") from e
