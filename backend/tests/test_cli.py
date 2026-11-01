"""Operations CLI: migrations, orgs/users, key generation, encrypting legacy rows."""
import io
import json
import uuid

import psycopg
import pytest

from app import cli
from app.core import config as cfg
from app.core import crypto, tenancy
from app.core import db as dbmod
from app.core import persist
from tests.conftest import system_scope


def test_gen_key_and_check_config(capsys, monkeypatch):
    assert cli.main(["gen-key"]) == 0
    key = capsys.readouterr().out.strip()
    assert len(key) == 44                                  # a valid Fernet key
    monkeypatch.setattr(cfg, "DATA_ENCRYPTION_KEYS", [])
    assert cli.main(["check-config"]) == 1                 # dev defaults are not production-ready
    assert "DATA_ENCRYPTION_KEYS" in capsys.readouterr().out
    assert cfg.ENV == "development"                        # the check never leaks the temporary override
    for attr, val in (("JWT_SECRET", "x" * 40), ("REQUIRE_AUTH", True), ("ADMIN_PASSWORD", "Str0ng!Passw0rd#1"),
                      ("CORS_ORIGINS", ["https://a.example"]), ("TRUSTED_HOSTS", ["api.example"]),
                      ("DATA_ENCRYPTION_KEYS", [key]), ("DATABASE_URL", "postgresql://x"),
                      ("PASSWORD_HASH_ITERATIONS", 210000)):
        monkeypatch.setattr(cfg, attr, val)
    assert cli.main(["check-config"]) == 0
    assert "OK" in capsys.readouterr().out


@pytest.mark.skipif(dbmod.RLS_ENABLED, reason="DDL needs the owner role, not the row-level-security app role")
def test_migrate_is_idempotent_and_tracked(capsys):
    assert cli.main(["migrate"]) == 0
    first = capsys.readouterr().out
    assert "applied migrate_005.sql" in first
    assert cli.main(["migrate"]) == 0
    second = capsys.readouterr().out
    assert "applied" not in second and "skip   migrate_005.sql" in second


def test_create_org_and_user(capsys, monkeypatch):
    org = "ORG-" + uuid.uuid4().hex[:6].upper()
    assert cli.main(["create-org", org, "Acme"]) == 0
    email = f"ops-{uuid.uuid4().hex[:6]}@example.com"
    monkeypatch.setattr("sys.stdin", io.StringIO("Str0ng!Passw0rd#1\n"))
    assert cli.main(["create-user", email, "Ops", "APPROVER", "--org", org]) == 0
    assert org in capsys.readouterr().out
    from app.core import security as sec
    u = sec._user_by_email(email)
    assert u["org_id"] == org and u["role"] == "APPROVER" and u["must_change_password"] is True
    monkeypatch.setattr("sys.stdin", io.StringIO("weak\n"))
    assert cli.main(["create-user", f"w-{email}", "W", "VIEWER"]) == 1   # policy enforced on the CLI too
    assert "weak password" in capsys.readouterr().out


def test_encrypt_existing_and_rotation(capsys, monkeypatch):
    cid = "CFG-" + uuid.uuid4().hex[:8].upper()
    plain = "snmp-server community LegacySecret RO\n"
    legacy = json.dumps({"configuration_id": cid, "config_text": plain, "status": "UPLOADED"})
    with psycopg.connect(dbmod.DATABASE_URL, autocommit=True) as raw:   # a pre-encryption (legacy) row
        system_scope(raw).execute("INSERT INTO configurations (configuration_id, config_text, data) VALUES (%s, %s, %s::jsonb)",
                    (cid, plain, legacy))
    assert persist.get("configurations", cid)["config_text"] == plain   # legacy rows still readable
    assert cli.main(["encrypt-existing"]) == 0
    assert "re-protected" in capsys.readouterr().out
    with psycopg.connect(dbmod.DATABASE_URL) as raw:
        col, js = system_scope(raw).execute("SELECT config_text, data->>'config_text' FROM configurations "
                              "WHERE configuration_id=%s", (cid,)).fetchone()
    assert col.startswith("enc:v1:") and js.startswith("enc:v1:")
    assert persist.get("configurations", cid)["config_text"] == plain
    # key rotation: new key first, then re-encrypt everything with it
    old_ring = list(cfg.DATA_ENCRYPTION_KEYS) or [crypto._DEV_KEY]   # rotation keeps the old key in the ring
    new_key = crypto.generate_key()
    monkeypatch.setattr(cfg, "DATA_ENCRYPTION_KEYS", [new_key] + old_ring)
    crypto.reset()
    before = persist.get("configurations", cid, inflate=False)["config_text"]
    assert cli.main(["reencrypt"]) == 0
    with psycopg.connect(dbmod.DATABASE_URL) as raw:
        after = system_scope(raw).execute("SELECT config_text FROM configurations WHERE configuration_id=%s", (cid,)).fetchone()[0]
    assert after != crypto.encrypt(plain) and after.startswith("enc:v1:")
    assert persist.get("configurations", cid)["config_text"] == plain and before == plain
    monkeypatch.undo()
    crypto.reset()
    with tenancy.unscoped():
        persist.delete("configurations", cid)


def test_cli_requires_db(monkeypatch):
    monkeypatch.setattr(dbmod, "DATABASE_URL", "")
    with pytest.raises(SystemExit):
        cli.main(["migrate"])
