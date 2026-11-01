"""Operations CLI:  python -m app.cli <command>

  gen-key                         print a new DATA_ENCRYPTION_KEYS value
  check-config                    validate the environment for production
  kms-wrap                        create a new data key wrapped by Vault/KMS (KEY_PROVIDER), print the wrapped form
  migrate                         apply schema.sql + migrate_*.sql (tracked in schema_migrations)
  anonymize IN OUT [--salt S] [--keep-text] [--map FILE]
                                  strip identifying data from a config (runs locally) so it can be shared for accuracy testing
  corpus-eval DIR [--json F] [--md F]
                                  score parse coverage, vendor detection and false-compliant on real configs
  catalogue-import FILE --framework F --license L --source S [--mapping M]
                                  import a control catalogue; unmapped entries report UNKNOWN, never PASS (docs/CATALOGUES.md)
  catalogue-coverage              per imported framework: entries vs entries with an automated check
  rls-enable | rls-disable | rls-status
                                  row-level security policies for tenant isolation (opt-in, see docs/SECURITY.md)
  create-org  ORG_ID NAME         create a tenant organisation
  create-user EMAIL NAME ROLE [--org ORG_ID]
                                  create a user (password read from stdin / prompt, never argv)
  encrypt-existing                encrypt legacy plaintext config rows in place (idempotent)
  reencrypt                       re-encrypt every protected field with the newest key (rotation)
"""
from __future__ import annotations
import argparse
import getpass
import json
import sys
from pathlib import Path

from app.core import config as cfg
from app.core import crypto, persist, rbac, tenancy
from app.core import db as dbmod

DB_DIR = Path(__file__).parent / "db"


def _need_db() -> None:
    if not dbmod.is_configured():
        sys.exit("DATABASE_URL is not set")


def cmd_gen_key(_: argparse.Namespace) -> int:
    print(crypto.generate_key())
    return 0


def cmd_check_config(_: argparse.Namespace) -> int:
    old = cfg.ENV
    cfg.ENV = "production"  # always validate against the production rules
    try:
        problems = cfg.validate_production()
    finally:
        cfg.ENV = old
    old_env = cfg.ENV
    cfg.ENV = "production"
    try:
        for w in cfg.production_warnings():
            print("warning:", w)
    finally:
        cfg.ENV = old_env
    if problems:
        print("NOT production-ready:")
        for p in problems:
            print(" -", p)
        return 1
    print("configuration OK for production")
    return 0


def cmd_kms_wrap(_: argparse.Namespace) -> int:
    """Generate a new data key, wrap it with the configured KMS/Vault, print ONLY the wrapped form."""
    from app.core import keyprovider
    try:
        print(keyprovider.wrap(crypto.generate_key()))
    except keyprovider.KeyProviderError as e:
        print("error:", e)
        return 1
    return 0


def _rls_info(cur) -> dict:
    cur.execute("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user")
    bypass = bool(cur.fetchone()[0])
    cur.execute("SELECT count(*) FILTER (WHERE c.relrowsecurity), count(*) FILTER (WHERE c.relforcerowsecurity) "
                "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = current_schema() AND c.relkind = 'r'")
    on, forced = cur.fetchone()
    return {"role_bypasses_rls": bypass, "tables_with_rls": on, "tables_forced": forced, "binding_enabled": dbmod.RLS_ENABLED}


def cmd_rls(a: argparse.Namespace) -> int:
    """rls-enable / rls-disable / rls-status (see docs/SECURITY.md, Row-level security)."""
    _need_db()
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        if a.cmd == "rls-enable":
            cur.execute((DB_DIR / "rls_enable.sql").read_text(encoding="utf-8"))
        elif a.cmd == "rls-disable":
            cur.execute((DB_DIR / "rls_disable.sql").read_text(encoding="utf-8"))
        info = _rls_info(cur)
    print(" ".join(f"{k}={v}" for k, v in info.items()))
    if a.cmd == "rls-enable":
        if info["role_bypasses_rls"]:
            print("note: this role is SUPERUSER/BYPASSRLS, so the policies do not protect it. Run the API as a plain role "
                  "(docs/SECURITY.md) and set RLS_ENABLED=true for it.")
        if not info["binding_enabled"]:
            print("note: RLS_ENABLED is not set in this process; a role subject to RLS would see no rows until it is.")
    return 0


def cmd_anonymize(a: argparse.Namespace) -> int:
    """Strip identifying data from a configuration (runs locally; nothing is uploaded)."""
    from app.services import anonymize
    src, dst = Path(a.input), Path(a.output)
    text, mapping = anonymize.anonymize(src.read_text(encoding="utf-8", errors="replace"), salt=a.salt, keep_text=a.keep_text)
    dst.write_text(text, encoding="utf-8")
    if a.map:
        Path(a.map).write_text(json.dumps(mapping, indent=2), encoding="utf-8")
        print(f"mapping written to {a.map} - keep it private, do not share it")
    print(f"wrote {dst} ({len(mapping)} identifiers replaced)")
    return 0


def cmd_corpus_eval(a: argparse.Namespace) -> int:
    """Score the product against a directory of real configs (read-only; needs DATABASE_URL for learned mappings)."""
    _need_db()
    from app.services import corpus_eval
    report = corpus_eval.evaluate_dir(Path(a.directory), a.frameworks.split(",") if a.frameworks else None)
    if a.json:
        Path(a.json).write_text(json.dumps(report, indent=2), encoding="utf-8")
    md = corpus_eval.to_markdown(report)
    if a.md:
        Path(a.md).write_text(md, encoding="utf-8")
    print(md)
    return 0 if report["summary"]["meets_pilot_bar"] else 2


def cmd_catalogue_import(a: argparse.Namespace) -> int:
    """Import a licensed / public control catalogue (see docs/CATALOGUES.md)."""
    import yaml
    from app.services import catalogue
    src = Path(a.file)
    data = src.read_bytes()
    try:
        fmt = a.format if a.format != "auto" else catalogue.detect_format(src.name, data)
        entries = {"xccdf": catalogue.parse_xccdf, "csv": catalogue.parse_csv, "json": catalogue.parse_json}[fmt](data)
        mapping = yaml.safe_load(Path(a.mapping).read_text(encoding="utf-8")) if a.mapping else None
        doc = catalogue.build(a.framework, entries, license_=a.license, source=a.source, mapping=mapping)
    except catalogue.CatalogueError as e:
        print("error:", e)
        return 1
    m = doc["_meta"]
    print(f"{m['framework']}: {m['total']} controls, {m['automated']} with an automated check, "
          f"{m['total'] - m['automated']} will report UNKNOWN (not assessed)")
    if a.dry_run:
        return 0
    print("wrote", catalogue.write(doc))
    return 0


def cmd_catalogue_coverage(_: argparse.Namespace) -> int:
    from app.services import catalogue
    rows = catalogue.coverage()
    for r in rows:
        print(f"{r['file']}: {r['automated']}/{r['total']} automated ({r['automated_pct']}%)")
    if not rows:
        print("no imported catalogues")
    return 0


def _migrations() -> list[str]:
    return ["schema.sql"] + sorted(p.name for p in DB_DIR.glob("migrate_*.sql"))


def cmd_migrate(_: argparse.Namespace) -> int:
    _need_db()
    with dbmod.get_conn() as conn:
        cur = conn.cursor()  # type: ignore[attr-defined]
        cur.execute("CREATE TABLE IF NOT EXISTS schema_migrations "
                    "(name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())")
        cur.execute("SELECT name FROM schema_migrations")
        done = {r[0] for r in cur.fetchall()}
        for name in _migrations():
            if name in done:
                print(f"skip   {name}")
                continue
            cur.execute((DB_DIR / name).read_text(encoding="utf-8"))
            cur.execute("INSERT INTO schema_migrations (name) VALUES (%s) ON CONFLICT DO NOTHING", (name,))
            print(f"applied {name}")
    return 0


def cmd_create_org(a: argparse.Namespace) -> int:
    _need_db()
    with dbmod.get_conn() as conn:
        conn.cursor().execute(  # type: ignore[attr-defined]
            "INSERT INTO organizations (org_id, name) VALUES (%s, %s) ON CONFLICT (org_id) DO UPDATE SET name=EXCLUDED.name",
            (a.org_id, a.name))
    print(f"organization {a.org_id} ready")
    return 0


def cmd_create_user(a: argparse.Namespace) -> int:
    _need_db()
    from app.core import security as sec
    pw = getpass.getpass("Password: ") if sys.stdin.isatty() else sys.stdin.readline().rstrip("\n")
    try:
        u = sec.create_user(a.email, a.name, pw, a.role, org_id=a.org, must_change=True)
    except ValueError as e:
        print("error:", e)
        return 1
    print(f"created {u['email']} ({u['role']}) in {u['org_id']}; password change required at first login")
    return 0


_ENC_TABLES = {"configurations": "configuration_id", "training": "training_id"}


def _reprotect(force: bool) -> int:
    _need_db()
    n = 0
    with tenancy.unscoped():
        for entity in _ENC_TABLES:
            for rec in persist.find(entity):          # decrypts transparently
                if force or any(isinstance(rec.get(f), str) and not crypto.is_encrypted(rec.get(f))
                                for f in persist._ENCRYPTED[entity]):
                    persist.save(entity, rec)         # re-encrypts with the newest key
                    n += 1
    print(f"re-protected {n} record(s)")
    return 0


def cmd_encrypt_existing(_: argparse.Namespace) -> int:
    return _reprotect(force=False)


def cmd_reencrypt(_: argparse.Namespace) -> int:
    return _reprotect(force=True)


def cmd_retention(a: argparse.Namespace) -> int:
    _need_db()
    import json
    from app.services import retention
    print(json.dumps(retention.run(dry_run=a.dry_run), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.cli", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("gen-key").set_defaults(fn=cmd_gen_key)
    sub.add_parser("check-config").set_defaults(fn=cmd_check_config)
    ci = sub.add_parser("catalogue-import", help="import a control catalogue (DISA STIG XCCDF / CSV / JSON)")
    ci.add_argument("file")
    ci.add_argument("--framework", required=True, help="e.g. STIG, CIS, ISO27001")
    ci.add_argument("--license", required=True, help="licence / terms under which you hold this catalogue")
    ci.add_argument("--source", required=True, help="where it came from (URL or document)")
    ci.add_argument("--format", choices=["auto", "xccdf", "csv", "json"], default="auto")
    ci.add_argument("--mapping", default="", help="YAML: {control-id: {condition: {...}, severity: HIGH}} to enable automated checks")
    ci.add_argument("--dry-run", action="store_true")
    ci.set_defaults(fn=cmd_catalogue_import)
    sub.add_parser("catalogue-coverage").set_defaults(fn=cmd_catalogue_coverage)
    an = sub.add_parser("anonymize", help="remove identifying data from a config so it can be shared for testing")
    an.add_argument("input")
    an.add_argument("output")
    an.add_argument("--salt", default="", help="secret salt: with the same salt the same address always maps to the same fake one")
    an.add_argument("--keep-text", action="store_true", help="keep descriptions / remarks / banners (default: remove them)")
    an.add_argument("--map", default="", help="write original->replacement mapping here (keep private)")
    an.set_defaults(fn=cmd_anonymize)
    ce = sub.add_parser("corpus-eval", help="score parsing / detection / false-compliant on a directory of real configs")
    ce.add_argument("directory")
    ce.add_argument("--json", default="")
    ce.add_argument("--md", default="")
    ce.add_argument("--frameworks", default="")
    ce.set_defaults(fn=cmd_corpus_eval)
    sub.add_parser("kms-wrap").set_defaults(fn=cmd_kms_wrap)
    sub.add_parser("migrate").set_defaults(fn=cmd_migrate)
    for n in ("rls-enable", "rls-disable", "rls-status"):
        sub.add_parser(n).set_defaults(fn=cmd_rls)
    o = sub.add_parser("create-org")
    o.add_argument("org_id")
    o.add_argument("name")
    o.set_defaults(fn=cmd_create_org)
    u = sub.add_parser("create-user")
    u.add_argument("email")
    u.add_argument("name")
    u.add_argument("role", choices=rbac.ROLES)
    u.add_argument("--org", default=cfg.DEFAULT_ORG_ID)
    u.set_defaults(fn=cmd_create_user)
    sub.add_parser("encrypt-existing").set_defaults(fn=cmd_encrypt_existing)
    sub.add_parser("reencrypt").set_defaults(fn=cmd_reencrypt)
    rt = sub.add_parser("retention", help="apply data-retention policy (see docs/OPERATIONS.md)")
    rt.add_argument("--dry-run", action="store_true", help="report what would be purged without deleting")
    rt.set_defaults(fn=cmd_retention)
    a = p.parse_args(argv)
    with tenancy.unscoped():          # operator tooling is cross-tenant by nature
        return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
