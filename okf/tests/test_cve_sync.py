"""NVD normalisation (update field, fixed), incremental sync window, KEV enrichment, atomic KB (mocked HTTP)."""
from src.cve import nvd_client, kev, kb as kbmod
from src.cve.correlator import to_findings
from src.cve.version_range import match_record


def _item(match, kev_add=None):
    cve = {"id": "CVE-2099-0001", "descriptions": [{"lang": "en", "value": "x"}],
           "configurations": [{"nodes": [{"cpeMatch": [match]}]}]}
    if kev_add:
        cve["cisaExploitAdd"], cve["cisaActionDue"] = kev_add, "2099-02-01"
    return {"cve": cve}


def test_cpe_update_field_makes_exact_junos_version_matchable():
    rec = nvd_client.normalize_nvd_item(_item({"vulnerable": True,
        "criteria": "cpe:2.3:o:juniper:junos:20.4:r3-s2:*:*:*:*:*:*:*"}))
    av = rec["affected"][0]["affected_versions"]
    assert match_record("20.4R3-S2", av)["affected"] is True
    assert match_record("20.4R3-S3", av)["affected"] is False


def test_end_excluding_records_fixed_version():
    rec = nvd_client.normalize_nvd_item(_item({"vulnerable": True, "versionEndExcluding": "10.2.3",
        "criteria": "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*"}))
    av = rec["affected"][0]["affected_versions"]
    assert av[0]["fixed"] == "10.2.3"
    assert match_record("10.2.3-h4", av)["affected"] is False
    assert match_record("10.2.2-h1", av)["affected"] is True


def test_kev_flag_from_nvd_and_catalogue_and_severity_boost():
    rec = nvd_client.normalize_nvd_item(_item({"vulnerable": True, "criteria": "cpe:2.3:o:a:b:*:*:*:*:*:*:*:*"}, "2099-01-01"))
    assert rec["exploited"] is True and rec["kev_added"] == "2099-01-01"
    other = {"cve_id": "CVE-2099-0002"}
    assert kev.apply_kev([other], {"vulnerabilities": [{"cveID": "CVE-2099-0002", "dateAdded": "d", "dueDate": "e"}]}) == 1
    assert other["exploited"] and other["kev_due"] == "e"
    corr = {"matches": [{"status": "VULNERABLE", "cve_id": "CVE-X", "product": "p", "installed_version": "1",
                         "cvss": {"severity": "HIGH"}, "exploited": True, "kev_due": "e", "fixed_version": "2"}]}
    f = to_findings(corr)[0]
    assert f["severity"] == "CRITICAL" and "KEV" in f["title"] and f["risk"]["exploited_in_wild"]


def test_incremental_sync_uses_window_and_stops_on_short_page(monkeypatch, tmp_path):
    monkeypatch.setattr(kbmod, "VULN", tmp_path); monkeypatch.setattr(kbmod, "STORE", tmp_path / "cves.json")
    monkeypatch.setattr(kbmod, "META", tmp_path / "meta.json"); kbmod.VulnKB.invalidate()
    calls = []

    def fake(rpp, idx, q, **kw):
        calls.append(kw)
        return {"vulnerabilities": [_item({"vulnerable": True, "criteria": "cpe:2.3:o:a:b:*:*:*:*:*:*:*:*"})]}
    monkeypatch.setattr(nvd_client, "fetch_cves", fake)
    out = nvd_client.sync(pages=5, results_per_page=200, since_days=3)
    assert len(calls) == 1 and "last_mod_start" in calls[0] and out["added"] == 1
    assert not list(tmp_path.glob("*.tmp"))              # atomic write left no temp files
    kbmod.VulnKB.invalidate()
