"""Branch coverage for services and small core modules: analytics rules, risk exceptions, scheduler, events, audit service,
history, report packs, retention, anonymiser, catalogue importer and the collection vault."""
import runpy
import sys
import time
import types
import uuid

import httpx
import psycopg
import pytest

from app import cli
from app.core import config as cfg
from app.core import db as dbmod
from app.core import persist, risk_exceptions, schedules, tenancy, urlcheck
from app.engines import security as rules
from app.services import anonymize, audit_service, catalogue, collection, events, history, job_handlers, report_packs, retention
from app.services import integration, webhook_formats


def _id(p):
    return f"{p}-{uuid.uuid4().hex[:8].upper()}"


def _asset():
    aid = _id("AST")
    persist.save("assets", {"asset_id": aid, "name": "cov-" + aid})
    return aid


# ---------------------------------------------------------------- analytics rule DSL
def test_rule_validation_errors_and_leaf_operators(tmp_path):
    p = tmp_path / "r.yaml"
    p.write_text("signals: []\npaths:\n  - {id: p1, severity: HIGH, signals: []}\n", encoding="utf-8")
    with pytest.raises(rules.RuleError, match="needs signals"):
        rules.load_rules(p)
    with pytest.raises(rules.RuleError):
        rules._validate({}, "r")
    rules._validate({"not": {"prop": "X", "is_true": True}}, "r")
    flat = {"a": 5, "s": "text"}
    assert rules._leaf({"prop": "a", "present": True}, flat) and rules._leaf({"prop": "zz", "present": False}, flat)
    assert rules._leaf({"prop": "a", "ne": 4}, flat) and not rules._leaf({"prop": "zz", "ne": 4}, flat)
    assert rules._leaf({"prop": "s", "gte": 3}, flat) is False                       # str >= int is a TypeError -> no match
    assert rules._leaf({"prop": "a", "unknown_operator": 1}, flat) is False
    assert rules.props_of("not a dict") == [] and rules.props_of({"not": {"prop": "P"}}) == ["P"]


# ---------------------------------------------------------------- risk exceptions
def test_exception_requests_and_decisions_reject_invalid_transitions():
    aid = _asset()
    with pytest.raises(risk_exceptions.ExceptionError, match="required"):
        risk_exceptions.request(aid, "", "a perfectly good reason", 5, "alice")
    ex = risk_exceptions.request(aid, "C-1", "a perfectly good reason", 5, "alice")
    risk_exceptions.decide(ex["exception_id"], "REJECTED", "bob")
    with pytest.raises(risk_exceptions.ExceptionError, match="cannot revoke"):
        risk_exceptions.decide(ex["exception_id"], "REVOKED", "bob")
    ex2 = risk_exceptions.request(aid, "C-2", "another good reason", 5, "alice")
    with dbmod.get_conn() as conn:
        conn.cursor().execute("UPDATE finding_exceptions SET expires_at = now() - interval '1 day' WHERE exception_id=%s", (ex2["exception_id"],))
    with pytest.raises(risk_exceptions.ExceptionError, match="expired"):
        risk_exceptions.decide(ex2["exception_id"], "APPROVED", "bob")
    assert isinstance(risk_exceptions.active_set(aid), set)


# ---------------------------------------------------------------- scheduler
def test_one_failing_schedule_does_not_block_the_others(monkeypatch):
    monkeypatch.setattr(schedules, "_claim_due", lambda limit: [("SCH-1", cfg.DEFAULT_ORG_ID, "AST-X", [], True, "me"),
                                                                ("SCH-2", cfg.DEFAULT_ORG_ID, "AST-X", [], True, "me")])
    outcomes = iter([RuntimeError("boom"), "QUEUED"])

    def fire(s):
        o = next(outcomes)
        if isinstance(o, Exception):
            raise o
        return o
    monkeypatch.setattr(schedules, "_fire", fire)
    recorded = []
    monkeypatch.setattr(schedules, "_set_status", lambda sid, st: recorded.append((sid, st)))
    assert schedules.run_due() == 1 and recorded == [("SCH-1", "ERROR: RuntimeError"), ("SCH-2", "QUEUED")]


# ---------------------------------------------------------------- url validation
def test_url_port_and_empty_resolution_are_refused(monkeypatch):
    with pytest.raises(urlcheck.UnsafeURL, match="invalid port"):
        urlcheck.validate("https://example.com:0/hook")
    monkeypatch.setattr(urlcheck.socket, "getaddrinfo", lambda *a, **k: [])
    with pytest.raises(urlcheck.UnsafeURL, match="does not resolve"):
        urlcheck.validate("https://example.com/hook")


# ---------------------------------------------------------------- audit service
def test_finding_ids_are_deterministic_and_do_not_collide_at_scale():
    ids = {audit_service._fid("F", f"AUD-{n}", f"CTRL-{k}", k) for n in range(300) for k in range(100)}
    assert len(ids) == 30_000                                           # 24-bit ids collided in ~5,000
    assert audit_service._fid("F", "AUD-1", "C", 3) == audit_service._fid("F", "AUD-1", "C", 3)
    assert len(audit_service._fid("F", "AUD-1", "C", 3).split("-")[1]) == 16


CONFIG = "hostname R1\nip ssh version 2\nservice password-encryption\n"


def _cfg_for(asset):
    cid = _id("CFG")
    persist.save("configurations", {"configuration_id": cid, "asset_id": asset, "config_text": CONFIG, "filename": "r.cfg", "status": "UPLOADED"})
    return cid


def test_audit_degradation_notes_and_stale_cleanup_failures(monkeypatch):
    integration._ensure_bridge()
    import src
    with monkeypatch.context() as m:
        m.setattr(src, "vendor_parsers", types.SimpleNamespace(), raising=False)
        assert audit_service._parser_version() == "unknown"
    aid = _asset()
    det = {"vendor_id": "cisco", "vendor": "Cisco", "platform": "ios_xe", "method": "fallback:model-missing", "confidence": 0.5}
    real = audit_service.db.select
    monkeypatch.setattr(audit_service.db, "select", lambda t, *a, **k: (_ for _ in ()).throw(RuntimeError("db")) if t == "findings" else real(t, *a, **k))
    rec = audit_service.run_audit(asset_id=aid, configuration_id=_cfg_for(aid), config_text=CONFIG, frameworks=["CIS"], run_cve=False,
                                  run_pqc=False, run_security=False, detected=det)
    assert any("vendor model unavailable" in d for d in rec["degraded"])


# ---------------------------------------------------------------- events
def test_emit_never_raises_and_deliveries_handle_disabled_hooks_and_failures(monkeypatch):
    monkeypatch.setattr(events.webhooks, "matching", lambda e: (_ for _ in ()).throw(RuntimeError("db")))
    assert events.emit("audit.completed", {}) == 0

    class Boom:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, *a, **k):
            raise httpx.ConnectError("connection refused")
    monkeypatch.setattr(events.httpx, "Client", Boom)
    with pytest.raises(httpx.ConnectError):
        events._post_pinned([urlcheck.Pinned("https://203.0.113.5/h", {"Host": "x"}, None)], b"{}", {})

    base = {"webhook_id": "WH-1", "enabled": False, "url": "https://203.0.113.5/h", "format": "json", "secret": "s", "auth_header": None}
    monkeypatch.setattr(events.webhooks, "load_for_delivery", lambda wid: dict(base))
    job = {"payload": {"webhook_id": "WH-1", "event": "ping"}, "attempts": 1, "org_id": cfg.DEFAULT_ORG_ID}
    with pytest.raises(job_handlers.PermanentJobError, match="disabled"):
        events.deliver(job)
    logged = []
    monkeypatch.setattr(events.webhooks, "load_for_delivery", lambda wid: {**base, "enabled": True, "auth_header": "X-Key: topsecret"})
    monkeypatch.setattr(events.webhooks, "log_delivery", lambda *a: logged.append(a))
    monkeypatch.setattr(events.urlcheck, "pin", lambda url: [urlcheck.Pinned("https://203.0.113.5/h", {"Host": "x"}, None)])
    monkeypatch.setattr(events, "_post_pinned", lambda *a: (_ for _ in ()).throw(httpx.ConnectError("topsecret was in the error")))
    with pytest.raises(RuntimeError, match="delivery failed"):
        events.deliver(job)
    assert "topsecret" not in logged[-1][4] and "***" in logged[-1][4]
    monkeypatch.setattr(events.webhooks, "load_for_delivery", lambda wid: {**base, "enabled": True, "auth_header": "X-Key:"})
    with pytest.raises(RuntimeError):
        events.deliver(job)


# ---------------------------------------------------------------- history
def test_recent_changes_respects_the_limit_and_missing_configs_have_no_diff():
    org = "ORG-COV3-" + uuid.uuid4().hex[:6].upper()
    with dbmod.get_conn() as conn:
        conn.cursor().execute("INSERT INTO organizations (org_id, name) VALUES (%s, %s)", (org, org))
    with tenancy.use_org(org):
        with dbmod.get_conn() as conn:
            for i in range(3):
                conn.cursor().execute("INSERT INTO audit_snapshots (snapshot_id, org_id, asset_id, audit_id, changes) VALUES (%s,%s,%s,%s,%s::jsonb)",
                                      (_id("SNP"), org, "AST-X", "AUD-X", '{"new_critical_high": 2}'))
        assert len(history.recent_changes(since_days=1, limit=2)) == 2
    assert history.config_diff("CFG-NOPE-A", "CFG-NOPE-B") is None


# ---------------------------------------------------------------- integration helpers
def test_learned_mapping_cache_and_resilience(monkeypatch):
    integration.invalidate_learned("ORG-SOMEONE")
    integration.invalidate_learned()
    monkeypatch.setattr(integration, "_ensure_bridge", integration._ensure_bridge)
    integration._ensure_bridge()
    broken = types.SimpleNamespace(fingerprint=lambda t: (_ for _ in ()).throw(RuntimeError("parser bug")))
    with monkeypatch.context() as m:
        m.setitem(sys.modules, "src.vendor_parsers", broken)
        assert integration.fingerprint_vendor("hostname R1") is None
    assert isinstance(integration.m3_suggest("ip ssh version 2", "cisco"), list)


def test_a_bad_learned_mapping_row_is_skipped(monkeypatch):
    org = "ORG-COV4-" + uuid.uuid4().hex[:6].upper()
    with dbmod.get_conn() as conn:
        conn.cursor().execute("INSERT INTO organizations (org_id, name) VALUES (%s, %s)", (org, org))
    with tenancy.use_org(org):
        persist.save("mappings", {"id": _id("MAP"), "mapping_id": "x", "vendor": "cisco", "platform": "any", "source_token": "([unclosed",
                                  "canonical_property": "SSH.ENABLED", "canonical_value": True, "confidence": 1.0, "status": "approved"})
        integration.invalidate_learned()
        assert integration.learning_engine() is not None


# ---------------------------------------------------------------- job handlers
def test_audit_job_with_a_missing_asset_or_malformed_config_is_permanent(monkeypatch):
    aid = _asset()
    cid = _cfg_for(aid)
    with pytest.raises(job_handlers.PermanentJobError, match="asset not found"):
        job_handlers.audit({"payload": {"configuration_id": cid, "asset_id": "AST-NOPE"}})
    monkeypatch.setattr(audit_service, "run_audit", lambda **k: (_ for _ in ()).throw(KeyError("vendor_id")))
    with pytest.raises(job_handlers.PermanentJobError, match="audit rejected"):
        job_handlers.audit({"payload": {"configuration_id": cid, "asset_id": aid}})


# ---------------------------------------------------------------- report packs / retention / webhook formats
def test_fleet_pdf_without_history_and_signoff_without_content(monkeypatch):
    org = "ORG-COV5-" + uuid.uuid4().hex[:6].upper()
    with dbmod.get_conn() as conn:
        conn.cursor().execute("INSERT INTO organizations (org_id, name) VALUES (%s, %s)", (org, org))
    with tenancy.use_org(org):                                  # an organisation with no audit history yet
        assert report_packs.fleet_pdf(report_packs.fleet_data(30)).startswith(b"%PDF")
    rid = _id("REP")
    persist.save("reports", {"report_id": rid, "audit_id": None, "status": "COMPLETED", "format": "PDF"})
    with pytest.raises(report_packs.SignoffError, match="no content hash"):
        report_packs.sign(rid, {"email": "a@example.com"})


def test_retention_skips_when_another_run_holds_the_lock():
    other = psycopg.connect(dbmod.DATABASE_URL, autocommit=True)
    try:
        if dbmod.RLS_ENABLED:
            other.execute("SELECT set_config('app.org_id', '*', false)")
        other.execute("SELECT pg_advisory_lock(%s)", (retention._LOCK_KEY,))
        out = retention.run(dry_run=True)
        assert out["skipped"] == ["another retention run is in progress"]
    finally:
        other.close()


def test_cef_carries_failed_controls_and_new_critical_changes():
    line = webhook_formats.render_cef("audit.completed", {"id": "d1", "org_id": "o", "data": {"failed": 3, "changes": {"new_critical_high": 2}}}, "headline")
    assert "cn1=3" in line and "cn2=2" in line


# ---------------------------------------------------------------- anonymiser edge cases
def test_anonymiser_leaves_unparseable_addresses_and_special_addresses_alone():
    out, _ = anonymize.anonymize("ip a 999.999.1.1\nipv6 loop ::1\nipv6 ll fe80::1\nipv6 junk 1:2:3\nbanner motd ^C\nsecret text\n^C\n", keep_text=False)
    assert "999.999.1.1" in out and "::1" in out and "fe80::1" in out and "1:2:3" in out and "secret text" not in out


# ---------------------------------------------------------------- catalogue importer
def test_catalogue_size_limits_and_xccdf_rule_without_description(monkeypatch):
    monkeypatch.setattr(catalogue, "MAX_BYTES", 10)
    with pytest.raises(catalogue.CatalogueError, match="too large"):
        catalogue.parse_xccdf(b"x" * 11)
    with pytest.raises(catalogue.CatalogueError, match="too large"):
        catalogue.parse_csv(b"x" * 11)
    monkeypatch.setattr(catalogue, "MAX_BYTES", 10_000)
    rules_ = catalogue.parse_xccdf(b'<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1"><Rule id="r1" severity="low"><title>t</title></Rule></Benchmark>')
    assert rules_[0]["description"] == "" and rules_[0]["severity"] == "LOW"


# ---------------------------------------------------------------- collection vault
def test_collection_requires_a_target_and_a_credential(monkeypatch):
    monkeypatch.setattr(cfg, "COLLECT_ALLOW_LOOPBACK", True)
    from app.core import collector
    with pytest.raises(collector.CollectError, match="no longer exists"):
        collection._secret("CRD-NOPE")
    aid = _asset()
    with tenancy.use_org(cfg.DEFAULT_ORG_ID):
        collection.set_target(aid, "127.0.0.1", 22, "cisco_ios", None, "SHA256:" + "A" * 43)
        with pytest.raises(collector.CollectError, match="no credential"):
            collection.collect_now(aid)


# ---------------------------------------------------------------- CLI entry point
def test_cli_module_entry_point(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["cli", "gen-key"])
    with pytest.raises(SystemExit) as e:
        runpy.run_module("app.cli", run_name="__main__")
    assert e.value.code == 0 and len(capsys.readouterr().out.strip()) == 44
    assert cli.main(["gen-key"]) == 0 and time.time() > 0
