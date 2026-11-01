"""TOTP multi-factor authentication (RFC 6238, SHA-1, 6 digits, 30 s) - stdlib only, no extra dependency.

Secrets are encrypted at rest (Fernet, same keys as other field encryption). A code can be used once
(``mfa_last_step`` replay guard). Ten single-use recovery codes are stored only as SHA-256 hashes.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import List, Optional, Tuple
from urllib.parse import quote

from app.core import crypto
from app.core import db as dbmod

STEP = 30
DIGITS = 6
WINDOW = 1            # accept the previous/next 30 s step for clock drift


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return str(code).zfill(DIGITS)


def totp(secret_b32: str, at: Optional[float] = None) -> str:
    return _hotp(secret_b32, int((at if at is not None else time.time()) // STEP))


def verify(secret_b32: str, code: str, last_step: int = 0, at: Optional[float] = None) -> Optional[int]:
    """Return the matched time-step (to persist as the replay guard) or None. Constant-time compare."""
    code = (code or "").strip().replace(" ", "")
    if not (code.isdigit() and len(code) == DIGITS):
        return None
    now_step = int((at if at is not None else time.time()) // STEP)
    hit: Optional[int] = None
    for s in range(now_step - WINDOW, now_step + WINDOW + 1):
        if hmac.compare_digest(_hotp(secret_b32, s), code) and s > last_step:
            hit = s
    return hit


def otpauth_uri(secret_b32: str, email: str, issuer: str = "NetSec Compliance Auditor") -> str:
    return f"otpauth://totp/{quote(issuer)}:{quote(email)}?secret={secret_b32}&issuer={quote(issuer)}&digits={DIGITS}&period={STEP}"


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.strip().lower().replace("-", "").encode()).hexdigest()


def new_recovery_codes(n: int = 10) -> Tuple[List[str], List[str]]:
    """(plain codes shown once, hashes to store)."""
    plain = [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(n)]
    return plain, [_hash_code(c) for c in plain]


# ------------------------------------------------------------------ storage
def _row(user_id: str):
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("SELECT mfa_secret_enc, mfa_enabled, mfa_recovery, mfa_last_step FROM users WHERE id=%s", (user_id,))
        return cur.fetchone()


def status(user_id: str) -> dict:
    r = _row(user_id)
    return {"enabled": bool(r and r[1]), "recovery_codes_left": len(r[2] or []) if r else 0}


def begin_enrolment(user_id: str, email: str) -> dict:
    secret = new_secret()
    with dbmod.get_conn() as conn:
        conn.cursor().execute(  # type: ignore[attr-defined]
            "UPDATE users SET mfa_secret_enc=%s, mfa_enabled=false, mfa_recovery='[]'::jsonb, mfa_last_step=0 WHERE id=%s",
            (crypto.encrypt(secret), user_id))
    return {"secret": secret, "otpauth_uri": otpauth_uri(secret, email)}


def confirm_enrolment(user_id: str, code: str) -> Optional[List[str]]:
    """Activate MFA when the first code verifies. Returns the plain recovery codes (shown once) or None."""
    from psycopg.types.json import Jsonb
    r = _row(user_id)
    if not r or not r[0] or r[1]:
        return None
    step = verify(crypto.decrypt(r[0]) or "", code, int(r[3] or 0))
    if step is None:
        return None
    plain, hashes = new_recovery_codes()
    with dbmod.get_conn() as conn:
        conn.cursor().execute(  # type: ignore[attr-defined]
            "UPDATE users SET mfa_enabled=true, mfa_recovery=%s, mfa_last_step=%s, token_version=token_version+1 WHERE id=%s",
            (Jsonb(hashes), step, user_id))
    return plain


def check(user_id: str, code: str) -> bool:
    """Verify a TOTP code or burn a recovery code. Marks the used step so a captured code cannot be replayed."""
    from psycopg.types.json import Jsonb
    r = _row(user_id)
    if not r or not r[1] or not r[0]:
        return False
    step = verify(crypto.decrypt(r[0]) or "", code, int(r[3] or 0))
    if step is not None:
        # compare-and-set: of two concurrent requests carrying the same code only ONE can advance the step
        with dbmod.get_conn() as conn:
            cur = conn.cursor()  # type: ignore[attr-defined]
            cur.execute("UPDATE users SET mfa_last_step=%s WHERE id=%s AND COALESCE(mfa_last_step, 0) < %s", (step, user_id, step))
            return cur.rowcount == 1
    h = _hash_code(code)
    if h in list(r[2] or []):
        # atomic burn: the DELETE-style update only matches while the hash is still present
        with dbmod.get_conn() as conn:
            cur = conn.cursor()  # type: ignore[attr-defined]
            cur.execute("UPDATE users SET mfa_recovery = mfa_recovery - %s::text WHERE id=%s AND mfa_recovery @> %s",
                        (h, user_id, Jsonb([h])))
            return cur.rowcount == 1
    return False


def disable(user_id: str) -> None:
    with dbmod.get_conn() as conn:
        conn.cursor().execute(  # type: ignore[attr-defined]
            "UPDATE users SET mfa_enabled=false, mfa_secret_enc=NULL, mfa_recovery='[]'::jsonb, mfa_last_step=0, "
            "token_version=token_version+1 WHERE id=%s", (user_id,))
