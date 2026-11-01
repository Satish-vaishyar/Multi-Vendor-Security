"""Credential vault + collection targets + the collect operation (see app/core/collector.py for the SSH side)."""
from __future__ import annotations
import uuid
from typing import Any, Dict, List, Optional

from app.core import collector, crypto, tenancy
from app.core import db as dbmod


def _cur(conn):  # type: ignore[no-untyped-def]
    return conn.cursor()


# ------------------------------------------------------------------ credentials (secrets never leave this module)
def create_credential(name: str, username: str, secret: str, auth_type: str, created_by: Optional[str]) -> Dict[str, Any]:
    if auth_type not in ("password", "key"):
        raise ValueError("auth_type must be password or key")
    if not secret or len(secret) > 16384:
        raise ValueError("secret is empty or too large")
    cid = "CRD-" + uuid.uuid4().hex[:10].upper()
    org = tenancy.current_org()
    with dbmod.get_conn() as conn:
        c = _cur(conn)
        c.execute("SELECT 1 FROM device_credentials WHERE org_id=%s AND name=%s", (org, name))
        if c.fetchone():
            raise ValueError("a credential with this name already exists")
        c.execute("INSERT INTO device_credentials (credential_id, org_id, name, username, auth_type, secret_enc, created_by) "
                  "VALUES (%s,%s,%s,%s,%s,%s,%s)", (cid, org, name, username, auth_type, crypto.encrypt(secret), created_by))
    return {"credential_id": cid, "name": name, "username": username, "auth_type": auth_type}


def list_credentials() -> List[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        c = _cur(conn)
        c.execute("SELECT credential_id, name, username, auth_type, created_by, created_at FROM device_credentials "
                  "WHERE org_id=%s ORDER BY name", (tenancy.current_org(),))
        return [{"credential_id": r[0], "name": r[1], "username": r[2], "auth_type": r[3], "created_by": r[4],
                 "created_at": r[5].isoformat()} for r in c.fetchall()]


def delete_credential(credential_id: str) -> bool:
    with dbmod.get_conn() as conn:
        c = _cur(conn)
        c.execute("DELETE FROM device_credentials WHERE credential_id=%s AND org_id=%s", (credential_id, tenancy.current_org()))
        return c.rowcount == 1


def _secret(credential_id: str) -> Dict[str, str]:
    with dbmod.get_conn() as conn:
        c = _cur(conn)
        c.execute("SELECT username, auth_type, secret_enc FROM device_credentials WHERE credential_id=%s AND org_id=%s",
                  (credential_id, tenancy.current_org()))
        r = c.fetchone()
    if not r:
        raise collector.CollectError("the credential assigned to this device no longer exists")
    return {"username": r[0], "auth_type": r[1], "secret": crypto.decrypt(r[2]) or ""}


# ------------------------------------------------------------------ targets
_T_COLS = "asset_id, host, port, profile, credential_id, host_key, last_collected_at, last_status, last_error"


def _target_row(r) -> Dict[str, Any]:  # type: ignore[no-untyped-def]
    return {"asset_id": r[0], "host": r[1], "port": r[2], "profile": r[3], "credential_id": r[4], "host_key": r[5] or "",
            "last_collected_at": r[6].isoformat() if r[6] else None, "last_status": r[7], "last_error": r[8]}


def get_target(asset_id: str) -> Optional[Dict[str, Any]]:
    with dbmod.get_conn() as conn:
        c = _cur(conn)
        c.execute(f"SELECT {_T_COLS} FROM collection_targets WHERE asset_id=%s AND org_id=%s", (asset_id, tenancy.current_org()))
        r = c.fetchone()
    return _target_row(r) if r else None


def set_target(asset_id: str, host: str, port: int, profile: str, credential_id: Optional[str], host_key: str) -> Dict[str, Any]:
    if profile not in collector.PROFILES:
        raise ValueError(f"profile must be one of {sorted(collector.PROFILES)}")
    try:
        collector.check_target(host, port)               # refuses metadata / loopback / out-of-range now, not at run time
    except collector.CollectError as e:
        raise ValueError(str(e))
    org = tenancy.current_org()
    with dbmod.get_conn() as conn:
        c = _cur(conn)
        c.execute("SELECT 1 FROM assets WHERE asset_id=%s AND org_id=%s", (asset_id, org))
        if not c.fetchone():
            raise LookupError("asset not found")
        if credential_id:
            c.execute("SELECT 1 FROM device_credentials WHERE credential_id=%s AND org_id=%s", (credential_id, org))
            if not c.fetchone():
                raise ValueError("credential not found")
        c.execute(
            "INSERT INTO collection_targets (asset_id, org_id, host, port, profile, credential_id, host_key) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (asset_id) DO UPDATE SET host=EXCLUDED.host, port=EXCLUDED.port, "
            "profile=EXCLUDED.profile, credential_id=EXCLUDED.credential_id, host_key=EXCLUDED.host_key, updated_at=now() "
            "WHERE collection_targets.org_id = EXCLUDED.org_id",
            (asset_id, org, host, port, profile, credential_id, host_key.strip()))
    return get_target(asset_id) or {}


def _status(asset_id: str, status: str, error: Optional[str]) -> None:
    with dbmod.get_conn() as conn:
        _cur(conn).execute(
            "UPDATE collection_targets SET last_status=%s, last_error=%s, "
            "last_collected_at=CASE WHEN %s='OK' THEN now() ELSE last_collected_at END WHERE asset_id=%s AND org_id=%s",
            (status, (error or "")[:500] or None, status, asset_id, tenancy.current_org()))


def collect_now(asset_id: str, factory: Optional[collector.TransportFactory] = None) -> Dict[str, Any]:
    """Collect the device's configuration and register it exactly like an upload. Returns the configuration record."""
    from app.api.v1.configurations import _register
    t = get_target(asset_id)
    if not t:
        raise collector.CollectError("no collection target is configured for this asset")
    if not t["credential_id"]:
        raise collector.CollectError("no credential is assigned to this device")
    cred = _secret(t["credential_id"])
    try:
        text = collector.collect(host=t["host"], port=t["port"], profile=t["profile"], username=cred["username"],
                                 secret=cred["secret"], auth_type=cred["auth_type"], pinned_fingerprint=t["host_key"],
                                 factory=factory)
        rec = _register(f"{asset_id}-live.cfg", text.encode("utf-8"), asset_id, collector.PROFILES[t["profile"]].vendor_hint)
    except (collector.CollectError, ValueError) as e:
        _status(asset_id, "FAILED", str(e))
        raise collector.CollectError(str(e))
    _status(asset_id, "OK", None)
    return rec
