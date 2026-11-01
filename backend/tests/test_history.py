"""Audit history, drift, finding age, trends, config diffs and recurring audit schedules."""
import threading
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import worker
from app.core import config as cfg
from app.core import db as dbmod
from app.core import jobs, schedules, tenancy
from app.main import app
from app.services import history

client = TestClient(app)
CORPUS = Path(cfg.OKF_DIR) / "tests" / "corpus"
HARDENED = (CORPUS / "cisco_iosxe_core_hardened.cfg").read_text(encoding="utf-8")


def _sql(q, *a):
    with dbmod.get_conn() as conn:
        cur = conn.cursor()
        cur.execute(q, a)
        return cur.fetchall() if cur.description else None


def _asset(prefix="hist"):
    return client.post("/api/v1/assets", json={"name": f"{prefix}-{uuid.uuid4().hex[:6]}"}).json()["data"]["asset_id"]


def _audit(asset, text, name="r.cfg"):
    cid = client.post("/api/v1/configurations/upload", data={"asset_id": asset},
                      files={"file": (name, text.encode(), "text/plain")}).json()["data"]["configuration_id"]
    r = client.post("/api/v1/audits", json={"asset_id": asset, "configuration_id": cid, "run_cve": False,
                                            "frameworks": ["CIS", "NIST"]})
    assert r.status_code == 200, r.text
    return cid, r.json()["data"]["audit_id"]


def _weaken(text):
    """Introduce real regressions: telnet on the vty lines, a public community, plain-text enable password."""
    t = text.replace(" transport input ssh", " transport input all")
    return t.replace("snmp-server group MON v3 priv", "snmp-server community public RO\nsnmp-server group MON v3 priv")


def _snaps(asset):
    return client.get(f"/api/v1/history/assets/{asset}").json()["data"]["items"]


# -------------------------------------------------------------------------- finding keys
def test_finding_keys_are_stable_across_runs():
    assert history.finding_key({"engine": "compliance", "control_id": "OKF-X"}) == "compliance:OKF-X"
    assert history.finding_key({"engine": "cve", "source": {"cve": "cve-2024-1"}}) == "cve:CVE-2024-1"
    assert history.finding_key({"engine": "cve", "title": "CVE-2023-20198: ios_xe 17.9 VULNERABLE"}) == "cve:CVE-2023-20198"
    assert history.finding_key({"engine": "pqc", "evidence": {"observed": {"algorithm": "RSA-1024", "protocol": "ssh"}}}) == "pqc:RSA-1024:ssh"
    assert history.finding_key({"engine": "security", "source": {"analytics": "LEGACY_SERVICE"},
                                "evidence": {"property": "TELNET.ENABLED"}}) == "security:LEGACY_SERVICE:TELNET.ENABLED"
    comp = history.compact_findings([{"engine": "compliance", "control_id": "A", "status": "PASS", "severity": "HIGH"},
                                     {"engine": "compliance", "control_id": "B", "status": "FAIL", "severity": "HIGH", "title": "t"},
                                     {"engine": "compliance", "control_id": "C", "status": "NOT_APPLICABLE", "severity": "LOW"},
                                     {"engine": "compliance", "control_id": "D", "status": "UNKNOWN", "severity": "LOW"}])
    assert [x["k"] for x in comp] == ["compliance:B", "compliance:D"]       # passing / N-A are not stored


def test_diff_findings_classifies_changes():
    f = lambda k, sev="HIGH", st="FAIL": {"k": k, "st": st, "sev": sev, "t": k, "e": "x"}  # noqa: E731
    d = history.diff_findings([f("a"), f("b", "MEDIUM"), f("c")], [f("b", "CRITICAL"), f("c"), f("d")])
    assert [x["k"] for x in d["new"]] == ["d"] and [x["k"] for x in d["resolved"]] == ["a"]
    assert [x["k"] for x in d["severity_increased"]] == ["b"] and d["unchanged"] == 2
    unknown_only = history.diff_findings([], [f("u", st="UNKNOWN")])
    assert unknown_only["new"] == []                                         # "could not assess" is not a new failure


# ------------------------------------------------------------------- drift between real runs
def test_regression_and_recovery_are_detected_between_audit_runs():
    asset = _asset()
    _audit(asset, HARDENED)
    _audit(asset, _weaken(HARDENED))
    snaps = _snaps(asset)
    assert len(snaps) == 2 and snaps[0]["changes"]["config_changed"] is True
    ch = snaps[0]["changes"]
    assert ch["new"] >= 2 and ch["new_critical_high"] >= 1 and ch["score_delta"] < 0 and ch["knowledge_changed"] == []
    cmp = client.get(f"/api/v1/history/assets/{asset}/compare").json()["data"]           # defaults: previous -> latest
    new_keys = {x["k"] for x in cmp["new"]}
    assert {"compliance:OKF-TELNET-001", "compliance:OKF-SNMP-001"} <= new_keys
    assert cmp["resolved"] == [] and cmp["score_delta"] < 0 and cmp["config_changed"] is True
    assert cmp["from"]["snapshot_id"] == snaps[1]["snapshot_id"] and cmp["to"]["snapshot_id"] == snaps[0]["snapshot_id"]
    _audit(asset, HARDENED)                                                              # fix it again
    back = client.get(f"/api/v1/history/assets/{asset}/compare").json()["data"]
    assert {"compliance:OKF-TELNET-001", "compliance:OKF-SNMP-001"} <= {x["k"] for x in back["resolved"]}
    assert back["score_delta"] > 0 and back["new"] == []
    assert len(_snaps(asset)) == 3


def test_same_config_rerun_is_recorded_so_knowledge_drift_is_visible():
    asset = _asset()
    _audit(asset, HARDENED)
    _audit(asset, HARDENED)                       # the audits row is upserted (same id) but history keeps both runs
    snaps = _snaps(asset)
    assert len(snaps) == 2 and snaps[0]["changes"]["config_changed"] is False and snaps[0]["changes"]["new"] == 0


def test_knowledge_change_is_reported_as_the_cause():
    asset = _asset()
    base = {"asset_id": asset, "audit_id": "AUD-K", "config_sha256": "same", "configuration_id": None,
            "summary": {"compliance_score": 90.0, "coverage_pct": 95.0}, "findings": [], "versions": {"cve_kb": "v1", "okf": "1.0"}}
    history.record_snapshot(base)
    second = {**base, "versions": {"cve_kb": "v2", "okf": "1.0"},
              "findings": [{"engine": "cve", "status": "FAIL", "severity": "CRITICAL", "source": {"cve": "CVE-2026-0001"}, "title": "x"}]}
    out = history.record_snapshot(second)
    assert out["config_changed"] is False and out["knowledge_changed"] == ["cve_kb"]
    assert out["new"] == 1 and out["new_critical_high"] == 1       # a new CVE appeared although the config did not change


# ------------------------------------------------------------------------------ aging / trend
def _fake(asset, fails, score, days_ago):
    snap = history.record_snapshot({"asset_id": asset, "audit_id": f"AUD-{uuid.uuid4().hex[:5]}", "config_sha256": uuid.uuid4().hex,
                                    "summary": {"compliance_score": score, "coverage_pct": 90, "CRITICAL": len(fails), "failed": len(fails)},
                                    "findings": [{"engine": "compliance", "control_id": c, "status": "FAIL", "severity": "HIGH", "title": c}
                                                 for c in fails], "versions": {}})
    _sql("UPDATE audit_snapshots SET created_at = now() - make_interval(days => %s) WHERE snapshot_id=%s", days_ago, snap["snapshot_id"])
    return snap["snapshot_id"]


def test_finding_age_counts_only_the_unbroken_streak():
    asset = _asset("age")
    _fake(asset, ["A", "B"], 70, 30)
    _fake(asset, ["A"], 80, 20)              # B fixed
    _fake(asset, ["A", "B"], 70, 10)         # B comes back
    last = _fake(asset, ["A", "B"], 70, 0)
    first = _snaps(asset)[-1]["snapshot_id"]
    cmp = client.get(f"/api/v1/history/assets/{asset}/compare", params={"from": first, "to": last}).json()["data"]
    ages = {x["k"]: x["age_days"] for x in cmp["persisting"]}
    assert 29.5 <= ages["compliance:A"] <= 30.5           # open since the first run
    assert 9.5 <= ages["compliance:B"] <= 10.5            # B's clock restarted when it re-opened


def test_trend_and_change_feed():
    asset = _asset("trend")
    _fake(asset, ["A"], 60, 5)
    _fake(asset, [], 90, 0)
    pts = client.get("/api/v1/history/trend", params={"days": 30, "asset_id": asset}).json()["data"]["points"]
    assert [p["score"] for p in pts] == [60.0, 90.0] and pts[0]["day"] < pts[1]["day"]
    assert client.get("/api/v1/history/trend", params={"days": 30, "asset_id": "AST-NOPE"}).status_code == 404
    org = client.get("/api/v1/history/trend", params={"days": 30}).json()["data"]["points"]
    assert org and all({"day", "score", "critical", "assets"} <= set(p) for p in org)
    asset2 = _asset("feed")
    _fake(asset2, [], 95, 3)
    _fake(asset2, ["X"], 60, 0)                           # new HIGH finding + 35 point drop = notable
    feed = client.get("/api/v1/history/changes", params={"days": 7}).json()["data"]["items"]
    mine = [i for i in feed if i["asset_id"] == asset2]
    assert mine and mine[0]["changes"]["new_critical_high"] == 1 and mine[0]["changes"]["score_delta"] == -35.0
    assert mine[0]["asset_name"].startswith("feed-")
    quiet = _asset("quiet")
    _fake(quiet, ["Y"], 80, 2)
    _fake(quiet, ["Y"], 80, 0)                            # nothing changed -> not in the notable feed, but in ?all=true
    assert not [i for i in client.get("/api/v1/history/changes", params={"days": 7}).json()["data"]["items"] if i["asset_id"] == quiet]
    assert [i for i in client.get("/api/v1/history/changes", params={"days": 7, "all": "true"}).json()["data"]["items"] if i["asset_id"] == quiet]


def test_purge_keeps_each_assets_recent_snapshots():
    asset = _asset("purge")
    ids = [_fake(asset, [], 90, d) for d in (400, 380, 1)]
    removed = history.purge(older_than_days=365, keep_last=1)
    left = {s["snapshot_id"] for s in history.list_snapshots(asset)}
    assert ids[2] in left and ids[0] not in left and removed >= 2
    assert len(left) >= 1


# ------------------------------------------------------------------------------ config diff
def test_config_diff_masks_secrets_and_counts_changed_secrets():
    asset = _asset("cdiff")
    a = "hostname R1\nip http server\nsnmp-server community OldSecret123 RO\nenable secret 5 $1$aaaa$OLDHASH\n"
    b = "hostname R1\nno ip http server\nsnmp-server community NewSecret456 RO\nenable secret 5 $1$aaaa$OLDHASH\nntp server 10.0.0.1\n"
    _audit(asset, a)
    _audit(asset, b)
    s = _snaps(asset)
    d = client.get(f"/api/v1/history/assets/{asset}/config-diff", params={"from": s[1]["snapshot_id"], "to": s[0]["snapshot_id"]}).json()["data"]
    text = "\n".join(d["diff"])
    assert "-ip http server" in text and "+no ip http server" in text and "+ntp server 10.0.0.1" in text
    assert "OldSecret123" not in text and "NewSecret456" not in text and "OLDHASH" not in text   # never leaked
    assert d["secret_lines_changed"] == 1 and d["identical"] is False and d["added"] >= 2 and d["removed"] >= 1
    same = client.get(f"/api/v1/history/assets/{asset}/config-diff", params={"from": s[0]["snapshot_id"], "to": s[0]["snapshot_id"]}).json()["data"]
    assert same["identical"] is True and same["diff"] == []


def test_history_api_errors_and_cross_asset_protection():
    one = _asset()
    assert client.get(f"/api/v1/history/assets/{one}/compare").status_code == 409        # nothing to compare yet
    _audit(one, HARDENED)
    assert client.get(f"/api/v1/history/assets/{one}/compare").status_code == 409
    other = _asset()
    _audit(other, HARDENED)
    s_one, s_other = _snaps(one)[0]["snapshot_id"], _snaps(other)[0]["snapshot_id"]
    assert client.get(f"/api/v1/history/assets/{one}/compare", params={"from": s_one, "to": s_other}).status_code == 404
    assert client.get(f"/api/v1/history/assets/{one}/config-diff", params={"from": s_one, "to": s_other}).status_code == 404
    assert client.get("/api/v1/history/assets/AST-NOPE").status_code == 404
    assert client.get(f"/api/v1/history/assets/{one}/compare", params={"from": "SNP-X", "to": "SNP-Y"}).status_code == 404


def test_history_is_tenant_isolated():
    asset = _asset("iso")
    sid = _fake(asset, ["A"], 70, 0)
    sched = client.post("/api/v1/schedules", json={"name": "iso", "asset_id": asset, "interval_minutes": 60}).json()["data"]["schedule_id"]
    _sql("INSERT INTO organizations (org_id,name) VALUES ('ORG-HX','HX') ON CONFLICT DO NOTHING")
    with tenancy.use_org("ORG-HX"):
        assert history.list_snapshots(asset) == []
        assert history.get_snapshot(sid) is None
        assert history.compare(asset, sid, sid) is None
        assert history.trend(30) == [] and history.recent_changes(7, only_notable=False) == []
        assert schedules.get(sched) is None and schedules.list_schedules() == []
        assert schedules.delete(sched) is False and schedules.run_now(sched) is None
    assert history.get_snapshot(sid) is not None and schedules.get(sched) is not None


def test_remediation_what_if_does_not_pollute_history():
    asset = _asset("whatif")
    _, aud = _audit(asset, _weaken(HARDENED))
    before = len(_snaps(asset))
    res = client.get(f"/api/v1/audits/{aud}/results").json()["data"]
    finding = next(f for f in res["findings"] if f.get("control_id") == "OKF-TELNET-001" and f["status"] == "FAIL")
    appr = client.post(f"/api/v1/remediation/{finding['finding_id']}/approve", json={"comment": "t"}).json()["data"]["id"]
    r = client.post(f"/api/v1/remediation/{finding['finding_id']}/apply", json={"id": appr, "updated_config_text": HARDENED})
    assert r.status_code == 200 and r.json()["data"]["verified_fixed"] is True
    assert len(_snaps(asset)) == before                   # the simulated re-audit is not a real run


# -------------------------------------------------------------------------------- schedules
def _config(asset, text=HARDENED):
    return client.post("/api/v1/configurations/upload", data={"asset_id": asset},
                       files={"file": ("s.cfg", text.encode(), "text/plain")}).json()["data"]["configuration_id"]


def test_schedule_validation():
    asset = _asset("sv")
    body = {"name": "n", "asset_id": asset}
    assert client.post("/api/v1/schedules", json={**body, "interval_minutes": 5}).status_code == 400          # below the minimum
    assert client.post("/api/v1/schedules", json={**body, "interval_minutes": 60, "frameworks": ["BOGUS"]}).status_code == 400
    assert client.post("/api/v1/schedules", json={"name": "n", "asset_id": "AST-NOPE", "interval_minutes": 60}).status_code == 404
    assert client.post("/api/v1/schedules", json={**body, "interval_minutes": 60 * 24 * 400}).status_code == 400
    ok = client.post("/api/v1/schedules", json={**body, "interval_minutes": 60, "start_in_minutes": 30})
    assert ok.status_code == 201
    sid = ok.json()["data"]["schedule_id"]
    s = client.get(f"/api/v1/schedules/{sid}").json()["data"]
    assert s["enabled"] is True and s["next_run_at"] > time.time() + 20 * 60 and s["last_run_at"] is None
    assert client.patch(f"/api/v1/schedules/{sid}", json={"interval_minutes": 3}).status_code == 400
    assert client.patch("/api/v1/schedules/SCH-NOPE", json={"enabled": False}).status_code == 404
    p = client.patch(f"/api/v1/schedules/{sid}", json={"name": "renamed", "frameworks": ["CIS"], "run_cve": False, "interval_minutes": 120}).json()["data"]
    assert p["name"] == "renamed" and p["frameworks"] == ["CIS"] and p["run_cve"] is False and p["interval_minutes"] == 120
    assert any(x["schedule_id"] == sid for x in client.get("/api/v1/schedules", params={"asset_id": asset}).json()["data"]["items"])
    assert client.delete(f"/api/v1/schedules/{sid}").status_code == 200 and client.delete(f"/api/v1/schedules/{sid}").status_code == 404
    assert client.get(f"/api/v1/schedules/{sid}").status_code == 404


def test_due_schedule_fires_once_audits_latest_config_and_reports_changes():
    asset = _asset("sf")
    c1 = _config(asset)
    _audit_id = client.post("/api/v1/audits", json={"asset_id": asset, "configuration_id": c1, "run_cve": False}).json()["data"]["audit_id"]
    sid = client.post("/api/v1/schedules", json={"name": "nightly", "asset_id": asset, "interval_minutes": 60, "run_cve": False}).json()["data"]["schedule_id"]
    _sql("UPDATE schedules SET next_run_at = now() - interval '1 minute' WHERE schedule_id=%s", sid)
    # the config changes before the scheduled run; the schedule must pick up the LATEST upload
    c2 = _config(asset, _weaken(HARDENED))
    assert schedules.run_due() >= 1
    s = client.get(f"/api/v1/schedules/{sid}").json()["data"]
    assert s["last_status"] == "QUEUED" and s["last_job_id"] and s["next_run_at"] > time.time() + 50 * 60
    job = client.get(f"/api/v1/jobs/{s['last_job_id']}").json()["data"]
    assert job["payload"]["configuration_id"] == c2 and job["payload"]["schedule_id"] == sid
    assert schedules.run_due() == 0                         # not due again until the interval passes
    worker.drain()
    done = client.get(f"/api/v1/jobs/{s['last_job_id']}").json()["data"]
    assert done["status"] == "COMPLETED"
    assert done["result"]["changes"]["new"] >= 2 and done["result"]["changes"]["config_changed"] is True
    snap = _snaps(asset)[0]
    assert snap["trigger"] == "schedule"


def test_disabled_schedules_do_not_fire_and_reenable_has_no_backlog():
    asset = _asset("sd")
    _config(asset)
    sid = client.post("/api/v1/schedules", json={"name": "x", "asset_id": asset, "interval_minutes": 60}).json()["data"]["schedule_id"]
    client.patch(f"/api/v1/schedules/{sid}", json={"enabled": False})
    _sql("UPDATE schedules SET next_run_at = now() - interval '5 days' WHERE schedule_id=%s", sid)
    schedules.run_due()
    assert client.get(f"/api/v1/schedules/{sid}").json()["data"]["last_job_id"] is None
    client.patch(f"/api/v1/schedules/{sid}", json={"enabled": True})
    assert client.get(f"/api/v1/schedules/{sid}").json()["data"]["next_run_at"] >= time.time() - 5     # missed days are not replayed


def test_schedule_without_config_and_run_now():
    asset = _asset("snc")
    sid = client.post("/api/v1/schedules", json={"name": "x", "asset_id": asset, "interval_minutes": 60}).json()["data"]["schedule_id"]
    r = client.post(f"/api/v1/schedules/{sid}/run")
    assert r.status_code == 409 and "no uploaded configuration" in r.text
    assert client.post("/api/v1/schedules/SCH-NOPE/run").status_code == 404
    _config(asset)
    ok = client.post(f"/api/v1/schedules/{sid}/run")
    assert ok.status_code == 200 and ok.json()["data"]["status"] == "QUEUED"
    assert client.get(f"/api/v1/schedules/{sid}").json()["data"]["last_status"] == "QUEUED"


def test_concurrent_schedulers_never_double_fire():
    asset = _asset("sc")
    _config(asset)
    sid = client.post("/api/v1/schedules", json={"name": "x", "asset_id": asset, "interval_minutes": 60}).json()["data"]["schedule_id"]
    _sql("UPDATE schedules SET next_run_at = now() - interval '1 minute' WHERE schedule_id=%s", sid)
    fired = []

    def tick():
        fired.append(schedules.run_due())

    ts = [threading.Thread(target=tick) for _ in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    mine = [j for j in _sql("SELECT payload->>'schedule_id' FROM jobs WHERE payload->>'schedule_id'=%s", sid)]
    assert len(mine) == 1                                     # six racing scheduler ticks, exactly one job


def test_schedule_limit_and_queue_full(monkeypatch):
    asset = _asset("sl")
    n = _sql("SELECT count(*) FROM schedules WHERE org_id=%s", tenancy.current_org())[0][0]
    monkeypatch.setattr(cfg, "MAX_SCHEDULES_PER_ORG", n)
    assert client.post("/api/v1/schedules", json={"name": "x", "asset_id": asset, "interval_minutes": 60}).status_code == 400
    monkeypatch.setattr(cfg, "MAX_SCHEDULES_PER_ORG", n + 10)
    sid = client.post("/api/v1/schedules", json={"name": "x", "asset_id": asset, "interval_minutes": 60}).json()["data"]["schedule_id"]
    _config(asset)
    base = _sql("SELECT count(*) FROM jobs WHERE org_id=%s AND status IN ('QUEUED','RUNNING')", tenancy.current_org())[0][0]
    monkeypatch.setattr(cfg, "MAX_QUEUED_JOBS_PER_ORG", base)
    assert client.post(f"/api/v1/schedules/{sid}/run").status_code == 409
    assert client.get(f"/api/v1/schedules/{sid}").json()["data"]["last_status"] == "QUEUE_FULL"
