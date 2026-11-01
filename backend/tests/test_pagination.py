"""Server-side pagination / sorting / search + dashboard aggregates (P2-7, N-4)."""
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core import persist
from app.core import rbac
from app.core import tenancy
from app.main import app
from app.services import dashboard
from tests.test_security import _auth_on, _headers, _org  # noqa: F401  (_auth_on: autouse fixture)

client = TestClient(app)


def _new_org() -> str:
    return _org("ORG-PG-" + uuid.uuid4().hex[:8].upper())


def _seed_assets(org: str, n: int, vendor: str = "cisco") -> list:
    ids = []
    with tenancy.use_org(org):
        for i in range(n):
            aid = f"AST-{uuid.uuid4().hex[:8].upper()}"
            persist.save("assets", {"asset_id": aid, "name": f"pg-dev-{i:03d}", "vendor": vendor,
                                    "product": "ios", "status": "ACTIVE", "criticality": "MEDIUM"})
            ids.append(aid)
    return ids


def _seed_audit(org: str, asset_id: str, score, fws=None, pqc=None) -> str:
    aid = f"AUD-{uuid.uuid4().hex[:8].upper()}"
    with tenancy.use_org(org):
        persist.save("audits", {"audit_id": aid, "asset_id": asset_id, "status": "COMPLETED",
                                "summary": {"compliance_score": score}, "by_framework": fws or {},
                                "pqc": pqc or {}})
    return aid


def _seed_finding(org: str, audit_id: str, asset_id: str, engine: str, sev: str, status: str,
                  control: str = "", title: str = "t") -> None:
    with tenancy.use_org(org):
        persist.save("findings", {"finding_id": f"FND-{uuid.uuid4().hex[:8].upper()}", "audit_id": audit_id,
                                  "asset_id": asset_id, "engine": engine, "type": "COMPLIANCE", "title": title,
                                  "severity": sev, "status": status, "control_id": control})


def _hdr(org: str) -> dict:
    return _headers(rbac.ADMIN, org)


# ------------------------------------------------------------------ helper level
def test_select_page_bounds_and_totals():
    org = _new_org()
    _seed_assets(org, 25)
    with tenancy.use_org(org):
        rows, total = persist.select_page("assets", None, page=1, page_size=10, sort="name", order="asc")
        assert total == 25 and len(rows) == 10 and rows[0]["name"] == "pg-dev-000"
        rows3, _ = persist.select_page("assets", None, page=3, page_size=10, sort="name", order="asc")
        assert len(rows3) == 5 and rows3[-1]["name"] == "pg-dev-024"
        rows9, t9 = persist.select_page("assets", None, page=9, page_size=10)
        assert rows9 == [] and t9 == 25
        # page_size is clamped to the hard maximum
        big, _ = persist.select_page("assets", None, page=1, page_size=10_000)
        assert len(big) == 25
        desc, _ = persist.select_page("assets", ["name"], page_size=3, sort="name", order="desc")
        assert [r["name"] for r in desc] == ["pg-dev-024", "pg-dev-023", "pg-dev-022"]


def test_select_page_rejects_bad_sort_order_and_search_cols():
    org = _new_org()
    with tenancy.use_org(org):
        for bad in ("created_at; drop table assets", "name desc", "data", "1=1", "evidence", "x"):
            with pytest.raises(ValueError):
                persist.select_page("assets", None, sort=bad)
        with pytest.raises(ValueError):
            persist.select_page("assets", None, order="asc; select 1")
        with pytest.raises(ValueError):
            persist.select_page("assets", None, q="x", search=("data",))
        with pytest.raises(ValueError):
            persist.select_page("assets", ["name; drop table assets"])
        with pytest.raises(ValueError):
            persist.select_page("assets", None, bogus="1")


def test_search_escapes_wildcards_and_binds_input():
    org = _new_org()
    with tenancy.use_org(org):
        for nm in ("alpha_1", "alphaX1", "100%core", "bravo"):
            persist.save("assets", {"asset_id": f"AST-{uuid.uuid4().hex[:8].upper()}", "name": nm,
                                    "status": "ACTIVE"})
        rows, total = persist.select_page("assets", ["name"], q="alpha_1", search=("name",))
        assert total == 1 and rows[0]["name"] == "alpha_1"      # '_' is literal, not a wildcard
        _, t = persist.select_page("assets", ["name"], q="%", search=("name",))
        assert t == 1                                            # only the literal '%'
        _, t = persist.select_page("assets", ["name"], q="x'; drop table assets;--", search=("name",))
        assert t == 0
        assert persist.count("assets") == 4                      # table intact


# ------------------------------------------------------------------ HTTP: assets
def test_assets_endpoint_pagination_sort_search_and_injection():
    org = _new_org()
    _seed_assets(org, 23)
    h = _hdr(org)
    d = client.get("/api/v1/assets?page=2&page_size=10&sort=name&order=asc", headers=h).json()["data"]
    assert d["total"] == 23 and d["page"] == 2 and d["page_size"] == 10
    assert [a["name"] for a in d["items"]][0] == "pg-dev-010" and len(d["items"]) == 10
    d = client.get("/api/v1/assets?q=dev-02&sort=name&order=desc", headers=h).json()["data"]
    assert d["total"] == 3 and d["items"][0]["name"] == "pg-dev-022"          # 020..022
    assert client.get("/api/v1/assets?page=0", headers=h).status_code == 422
    assert client.get("/api/v1/assets?page_size=101", headers=h).status_code == 422
    assert client.get("/api/v1/assets?order=sideways", headers=h).status_code == 422
    for bad in ("created_at;%20drop%20table%20assets", "data", "name%20desc"):
        r = client.get(f"/api/v1/assets?sort={bad}", headers=h)
        assert r.status_code == 400, bad
    assert client.get("/api/v1/assets", headers=h).json()["data"]["total"] == 23


def test_tenant_isolation_of_totals():
    a, b = _new_org(), _new_org()
    _seed_assets(a, 7)
    _seed_assets(b, 3)
    assert client.get("/api/v1/assets", headers=_hdr(a)).json()["data"]["total"] == 7
    assert client.get("/api/v1/assets", headers=_hdr(b)).json()["data"]["total"] == 3
    # search can never reach across tenants
    assert client.get("/api/v1/assets?q=pg-dev", headers=_hdr(b)).json()["data"]["total"] == 3


# ------------------------------------------------------------------ HTTP: findings
def test_findings_pagination_filters_and_totals():
    org = _new_org()
    (asset,) = _seed_assets(org, 1)
    aud = _seed_audit(org, asset, 80)
    for i in range(12):
        _seed_finding(org, aud, asset, "compliance", "HIGH" if i % 3 == 0 else "LOW",
                      "FAIL" if i % 2 == 0 else "PASS", control=f"CIS-{i}", title=f"finding {i:02d}")
    h = _hdr(org)
    d = client.get("/api/v1/findings?page_size=5&page=3&sort=title&order=asc", headers=h).json()["data"]
    assert d["total"] == 12 and len(d["items"]) == 2 and d["page"] == 3
    d = client.get("/api/v1/findings?severity=high&status=fail", headers=h).json()["data"]
    assert d["total"] == 2                                   # i = 0, 6
    d = client.get(f"/api/v1/findings?audit_id={aud}&q=finding 1", headers=h).json()["data"]
    assert d["total"] == 2                                   # "finding 10", "finding 11"
    assert client.get("/api/v1/findings?sort=evidence", headers=h).status_code == 400
    assert client.get("/api/v1/findings?sort=title;drop", headers=h).status_code == 400
    other = _new_org()
    assert client.get("/api/v1/findings", headers=_hdr(other)).json()["data"]["total"] == 0


def test_audits_reports_training_remediation_lists_paginate():
    org = _new_org()
    ids = _seed_assets(org, 6)
    for i, aid in enumerate(ids):
        _seed_audit(org, aid, 50 + i)
    h = _hdr(org)
    d = client.get("/api/v1/audits?page_size=4&page=2", headers=h).json()["data"]
    assert d["total"] == 6 and len(d["items"]) == 2 and d["page_size"] == 4
    assert client.get("/api/v1/audits?sort=summary", headers=h).status_code == 400
    r = client.get("/api/v1/reports?page_size=5", headers=h).json()["data"]
    assert r["total"] == 0 and r["items"] == [] and r["page"] == 1
    assert client.get("/api/v1/reports?limit=3", headers=h).json()["data"]["page_size"] == 3
    assert client.get("/api/v1/reports?sort=pdf", headers=h).status_code == 400
    with tenancy.use_org(org):
        for i in range(5):
            persist.save("training", {"training_id": f"TRN-{uuid.uuid4().hex[:8]}", "vendor": "cisco",
                                      "platform": "ios", "raw_command": f"cmd {i}", "status": "PENDING"})
    t = client.get("/api/v1/training/queue?page_size=2&page=3", headers=h).json()["data"]
    assert t["total"] == 5 and len(t["items"]) == 1
    assert client.get("/api/v1/training/queue?sort=raw_command", headers=h).status_code == 200  # whitelisted col
    assert client.get("/api/v1/training/queue?sort=context", headers=h).status_code == 400


# ------------------------------------------------------------------ dashboard
def test_dashboard_summary_matches_known_data():
    org = _new_org()
    a1, a2, a3 = _seed_assets(org, 2) + _seed_assets(org, 1, vendor="juniper")
    old = _seed_audit(org, a1, 10)                     # superseded: latest per asset wins
    new1 = _seed_audit(org, a1, 60, fws={"CIS": {"compliance_score": 50}, "NIST": {"compliance_score": "x"}},
                       pqc={"readiness_score": 40})
    new2 = _seed_audit(org, a2, 90, fws={"CIS": {"compliance_score": 100}}, pqc={"readiness_score": 60})
    _seed_finding(org, new1, a1, "compliance", "CRITICAL", "FAIL", "C-1", "one")
    _seed_finding(org, new1, a1, "compliance", "HIGH", "FAIL", "C-2", "two")
    _seed_finding(org, new2, a2, "compliance", "HIGH", "FAIL", "C-1", "one")
    _seed_finding(org, new2, a2, "compliance", "LOW", "PASS", "C-3", "three")
    _seed_finding(org, new2, a2, "cve", "CRITICAL", "OPEN", "", "cve-x")
    _seed_finding(org, old, a1, "pqc", "MEDIUM", "FAIL", "P-1", "pq")
    dashboard.clear_cache()
    r = client.get("/api/v1/dashboard/summary", headers=_hdr(org))
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["assets"] == {"total": 3, "healthy": 1, "at_risk": 2}        # a1,a2 fail high/critical; a3 clean
    assert d["findings"] == {"critical": 1, "high": 2, "medium": 1, "low": 0}
    assert d["by_severity"] == d["findings"]
    assert d["cve"] == {"critical": 1, "high": 0}
    assert d["by_engine"]["compliance"] == {"fail": 3, "total": 4}
    assert d["by_engine"]["pqc"]["fail"] == 1
    assert d["by_vendor"]["cisco"] == {"assets": 2, "failed_findings": 4}
    assert d["by_vendor"]["juniper"] == {"assets": 1, "failed_findings": 0}
    assert d["compliance"]["overall"] == 75.0                              # (60 + 90) / 2, old audit ignored
    assert d["frameworks"]["CIS"]["score"] == 75.0 and "NIST" not in d["frameworks"]
    assert d["pqc"] == {"audits": 2, "readiness": 50.0}
    dist = {b["range"]: b["count"] for b in d["score_distribution"]}
    assert dist["60-79"] == 1 and dist["80-100"] == 1 and sum(dist.values()) == 2
    top = d["top_failing_controls"]
    assert top[0]["control_id"] == "C-1" and top[0]["failures"] == 2 and top[0]["assets"] == 2
    assert [t["audit_id"] for t in d["trend"]] == [old, new1, new2]
    assert d["trend"][-1]["compliance_score"] == 90.0
    assert d["totals"] == {"findings": 6, "failed": 4}
    # a second tenant sees none of it
    other = client.get("/api/v1/dashboard/summary", headers=_hdr(_new_org())).json()["data"]
    assert other["assets"]["total"] == 0 and other["findings"]["critical"] == 0
    assert other["trend"] == [] and other["top_failing_controls"] == []


def test_dashboard_cache_ttl_per_org(monkeypatch):
    org, other = _new_org(), _new_org()
    now = [1000.0]
    monkeypatch.setattr(dashboard, "_clock", lambda: now[0])
    monkeypatch.setattr(dashboard, "TTL_SECONDS", 5.0)
    dashboard.clear_cache()
    calls = []
    real = dashboard._compute
    monkeypatch.setattr(dashboard, "_compute", lambda: (calls.append(tenancy.current_org()), real())[1])
    _seed_assets(org, 1)
    with tenancy.use_org(org):
        first = dashboard.summary()
        assert first["assets"]["total"] == 1
        _seed_assets(org, 1)                       # change data inside the TTL window
        assert dashboard.summary()["assets"]["total"] == 1 and len(calls) == 1   # served from cache
        now[0] += 5.1                              # TTL elapsed -> recomputed
        assert dashboard.summary()["assets"]["total"] == 2 and len(calls) == 2
    with tenancy.use_org(other):                   # separate cache entry per org
        assert dashboard.summary()["assets"]["total"] == 0 and len(calls) == 3
    dashboard.clear_cache()


# ------------------------------------------------------------------ vulnerabilities paging
def test_vulns_per_audit_paginates():
    org = _new_org()
    (asset,) = _seed_assets(org, 1)
    aid = f"AUD-{uuid.uuid4().hex[:8].upper()}"
    matches = [{"cve_id": f"CVE-2024-{i:04d}", "installed_version": "1", "cvss": {"severity": "HIGH"}}
               for i in range(7)]
    with tenancy.use_org(org):
        persist.save("audits", {"audit_id": aid, "asset_id": asset, "status": "COMPLETED",
                                "cve": {"matches": matches, "unresolved": []}})
    d = client.get(f"/api/v1/vulnerabilities/{aid}?page=2&page_size=3", headers=_hdr(org)).json()["data"]
    assert d["total"] == 7 and len(d["items"]) == 3 and d["summary"]["total"] == 7 and d["summary"]["high"] == 7
