"""Tools that turn a pilot into evidence: anonymiser, corpus evaluation, licensed-catalogue import."""
import json
import re
from pathlib import Path

import pytest

from app import cli
from app.core import config as cfg
from app.services import anonymize, catalogue, corpus_eval
from app.services.integration import okf_layer

CORPUS = cfg.OKF_DIR / "tests" / "corpus"
SAMPLE = """\
hostname core-rtr-bank-01
ip domain-name corp.bank-example.com
username alice privilege 15 secret 9 $9$abcdefghijklmnop
snmp-server community Sup3rPublic RO
snmp-server location Mumbai DC2 rack 14
interface GigabitEthernet0/1
 description UPLINK to bank HQ circuit 55-1234
 ip address 192.168.10.1 255.255.255.0
 ip access-group 101 in
access-list 101 permit ip 10.1.2.0 0.0.0.255 any
access-list 101 deny ip any any log
ip route 0.0.0.0 0.0.0.0 203.0.113.9
ntp server 8.8.8.8
interface Vlan10
 mac-address 00aa.bbcc.ddee
logging host 172.16.5.5
ipv6 address 2001:db8:abcd::1/64
contact admin@bank-example.com
banner motd ^C
Authorised users only. Property of Example Bank.
^C
line vty 0 4
 transport input ssh
"""


# ---------------------------------------------------------------- anonymiser
def test_identifying_data_is_replaced_and_syntax_is_preserved():
    out, mapping = anonymize.anonymize(SAMPLE, salt="s1")
    for leak in ("core-rtr-bank-01", "bank-example", "alice", "Sup3rPublic", "Mumbai", "192.168.10.1", "172.16.5.5",
                 "8.8.8.8", "203.0.113.9", "00aa.bbcc.ddee", "2001:db8:abcd", "UPLINK", "Example Bank", "admin@",
                 "abcdefghijklmnop"):
        assert leak not in out, leak
    for kept in ("255.255.255.0", "0.0.0.255", "0.0.0.0 0.0.0.0", "permit ip", "deny ip any any log", "transport input ssh",
                 "ip access-group 101 in", "line vty 0 4", "/64"):
        assert kept in out, kept
    assert out.splitlines()[0] == "hostname host1" and "username user1 privilege 15" in out
    assert len(out.splitlines()) >= len(SAMPLE.splitlines()) - 1            # structure (line count) survives
    assert "192.168.10.1" in mapping and mapping["192.168.10.1"].startswith("10.")        # private stays private
    assert mapping["8.8.8.8"].startswith("203.")                                          # public stays public


def test_mapping_is_consistent_and_salted():
    a, _ = anonymize.anonymize("ip a 10.9.9.9\nip b 10.9.9.9\nip c 10.9.9.8\n", salt="x")
    ips = re.findall(r"10\.\d+\.\d+\.\d+", a)
    assert ips[0] == ips[1] and ips[0] != ips[2]
    b, _ = anonymize.anonymize("ip a 10.9.9.9\n", salt="y")
    assert b != a.splitlines()[0] + "\n"
    again, _ = anonymize.anonymize("ip a 10.9.9.9\nip b 10.9.9.9\nip c 10.9.9.8\n", salt="x")
    assert again == a


def test_keep_text_keeps_descriptions_and_banners():
    out, _ = anonymize.anonymize(SAMPLE, keep_text=True)
    assert "UPLINK to bank HQ" in out and "Property of Example Bank" in out


@pytest.mark.parametrize("f", sorted(p.name for p in CORPUS.glob("*.cfg")))
def test_anonymising_a_real_sample_does_not_change_what_the_product_concludes(f, tmp_path):
    src = (CORPUS / f).read_text(encoding="utf-8")
    anon, _ = anonymize.anonymize(src, salt="pilot")
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / f).write_text(src, encoding="utf-8")
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / f).write_text(anon, encoding="utf-8")
    before = corpus_eval.evaluate_file(tmp_path / "a" / f)
    after = corpus_eval.evaluate_file(tmp_path / "b" / f)
    assert after["vendor_detected"] == before["vendor_detected"]
    assert after["controls"] == before["controls"]                               # same PASS / FAIL / UNKNOWN counts


# ---------------------------------------------------------------- corpus evaluation
def test_corpus_eval_scores_files_and_flags_false_compliant(tmp_path):
    insecure, hardened = "cisco_iosxe_branch_insecure.cfg", "cisco_iosxe_core_hardened.cfg"
    for n in (insecure, hardened):
        (tmp_path / n).write_text((CORPUS / n).read_text(encoding="utf-8"), encoding="utf-8")
    base = corpus_eval.evaluate_file(tmp_path / insecure)
    failing = base["controls"]["FAIL"]
    assert failing > 0 and base["vendor_detected"] == "cisco" and 0 < base["understood_pct"] <= 100
    # build truthful expectations from what the product reports, then add a deliberately wrong one
    okf = okf_layer()
    from app.parsers import canonical as canon, vendor_detector as vd
    text = (tmp_path / insecure).read_text(encoding="utf-8")
    det = vd.detect_vendor(text, "")
    parsed = canon.parse_to_canonical(text, det["vendor_id"], str(det.get("platform") or ""))
    findings = okf["ComplianceEngine"](okf["ckb"].all(), {}).evaluate(parsed["nested_ir"], vendor=det["vendor_id"],
                                                                      platform=str(det.get("platform") or ""),
                                                                      not_applicable=parsed.get("not_applicable"))
    fail_id = next(f.control_id for f in findings if f.status == "FAIL")
    pass_id = next(f.control_id for f in findings if f.status == "PASS")
    (tmp_path / (insecure + ".expect.json")).write_text(json.dumps({"vendor": "cisco", "must_fail": [fail_id, pass_id],
                                                                    "must_pass": [fail_id]}), encoding="utf-8")
    rep = corpus_eval.evaluate_dir(tmp_path)
    row = next(r for r in rep["files"] if r["file"] == insecure)
    assert row["vendor_ok"] is True and row["false_compliant"] == [pass_id] and row["false_alarm"] == [fail_id]
    s = rep["summary"]
    assert s["files"] == 2 and s["seeded_checks"] == 2 and s["false_compliant_total"] == 1 and s["meets_pilot_bar"] is False
    md = corpus_eval.to_markdown(rep)
    assert "meets the pilot bar" in md and "**NO**" in md and pass_id in md


def test_pilot_bar_requires_coverage_zero_false_compliant_and_seeded_checks(tmp_path, monkeypatch):
    n = "cisco_iosxe_branch_insecure.cfg"
    (tmp_path / n).write_text((CORPUS / n).read_text(encoding="utf-8"), encoding="utf-8")
    assert corpus_eval.evaluate_dir(tmp_path)["summary"]["meets_pilot_bar"] is False       # no seeded checks -> not proven
    row = corpus_eval.evaluate_file(tmp_path / n)
    fail_id = None
    from app.parsers import canonical as canon, vendor_detector as vd
    text = (tmp_path / n).read_text(encoding="utf-8")
    det = vd.detect_vendor(text, "")
    parsed = canon.parse_to_canonical(text, det["vendor_id"], str(det.get("platform") or ""))
    okf = okf_layer()
    for f in okf["ComplianceEngine"](okf["ckb"].all(), {}).evaluate(parsed["nested_ir"], vendor=det["vendor_id"], platform=str(det.get("platform") or ""),
                                                                    not_applicable=parsed.get("not_applicable")):
        if f.status == "FAIL":
            fail_id = f.control_id
            break
    (tmp_path / (n + ".expect.json")).write_text(json.dumps({"vendor": "cisco", "must_fail": [fail_id]}), encoding="utf-8")
    monkeypatch.setattr(corpus_eval, "PILOT_UNDERSTOOD_PCT", 0.0)
    assert corpus_eval.evaluate_dir(tmp_path)["summary"]["meets_pilot_bar"] is True
    monkeypatch.setattr(corpus_eval, "PILOT_UNDERSTOOD_PCT", 101.0)
    assert corpus_eval.evaluate_dir(tmp_path)["summary"]["meets_pilot_bar"] is False
    assert row["lines"] > 0


def test_a_broken_file_is_reported_not_fatal(tmp_path, monkeypatch):
    (tmp_path / "ok.cfg").write_text((CORPUS / "arista_eos_leaf.cfg").read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "bad.cfg").write_text("x", encoding="utf-8")
    (tmp_path / "bad.cfg.expect.json").write_text("{not json", encoding="utf-8")
    rep = corpus_eval.evaluate_dir(tmp_path)
    assert rep["summary"]["files"] == 1 and rep["summary"]["errors"] == 1 and rep["errors"][0]["file"] == "bad.cfg"
    assert "ERROR" in corpus_eval.to_markdown(rep)
    assert corpus_eval.evaluate_dir(tmp_path / "empty-nonexistent")["summary"]["files"] == 0


def test_cli_anonymize_and_corpus_eval(tmp_path, capsys):
    src, dst, mp = tmp_path / "in.cfg", tmp_path / "out.cfg", tmp_path / "map.json"
    src.write_text(SAMPLE, encoding="utf-8")
    assert cli.main(["anonymize", str(src), str(dst), "--salt", "z", "--map", str(mp)]) == 0
    assert "core-rtr-bank-01" not in dst.read_text(encoding="utf-8") and "core-rtr-bank-01" not in dst.name
    assert json.loads(mp.read_text(encoding="utf-8")) and "keep it private" in capsys.readouterr().out
    d = tmp_path / "corp"
    d.mkdir()
    (d / "a.cfg").write_text((CORPUS / "arista_eos_leaf.cfg").read_text(encoding="utf-8"), encoding="utf-8")
    rc = cli.main(["corpus-eval", str(d), "--json", str(tmp_path / "r.json"), "--md", str(tmp_path / "r.md")])
    assert rc == 2                                                       # no seeded checks -> the pilot bar is not met
    assert json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["summary"]["files"] == 1
    assert "Corpus evaluation" in (tmp_path / "r.md").read_text(encoding="utf-8")


# ---------------------------------------------------------------- catalogue import
XCCDF = b"""<?xml version="1.0" encoding="utf-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="Router_STIG">
 <Group id="V-1"><Rule id="SV-1r1_rule" severity="high"><version>CISC-RT-000010</version>
   <title>The router must not allow telnet.</title><description>Telnet is cleartext.</description></Rule></Group>
 <Group id="V-2"><Rule id="SV-2r1_rule" severity="medium"><version>CISC-RT-000020</version>
   <title>The router must log to a remote server.</title><description>Logging.</description></Rule></Group>
</Benchmark>"""


def test_parsers_accept_the_three_formats_and_reject_hostile_input():
    x = catalogue.parse_xccdf(XCCDF)
    assert [e["id"] for e in x] == ["CISC-RT-000010", "CISC-RT-000020"] and x[0]["severity"] == "HIGH" and x[1]["severity"] == "MEDIUM"
    c = catalogue.parse_csv(b"ID,Title,Severity\nCIS-1.1,Disable telnet,High\nCIS-1.2,Enable logging,Low\n,missing id,High\n")
    assert [e["id"] for e in c] == ["CIS-1.1", "CIS-1.2"] and c[0]["severity"] == "HIGH"
    j = catalogue.parse_json(json.dumps({"controls": [{"id": "A.8.1", "title": "Endpoint devices", "severity": "critical"}]}).encode())
    assert j[0]["severity"] == "CRITICAL"
    assert catalogue.parse_json(json.dumps([{"control_id": "X-1", "title": "t"}]).encode())[0]["id"] == "X-1"
    for bad in (b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><Benchmark><Rule id="r"/></Benchmark>',
                b"<Benchmark><Rule", b"<Benchmark/>"):
        with pytest.raises(catalogue.CatalogueError):
            catalogue.parse_xccdf(bad)
    for fn, bad in ((catalogue.parse_csv, b"a,b\n1,2\n"), (catalogue.parse_json, b"{nope"), (catalogue.parse_json, b'"str"'),
                    (catalogue.parse_json, b"[]")):
        with pytest.raises(catalogue.CatalogueError):
            fn(bad)
    assert catalogue.detect_format("a.xml", b"") == "xccdf" and catalogue.detect_format("a.json", b"{}") == "json" \
        and catalogue.detect_format("a.csv", b"id,title") == "csv" and catalogue.detect_format("noext", b"<?xml") == "xccdf"


def test_unmapped_controls_report_unknown_never_pass_and_mapped_ones_are_checked(tmp_path):
    entries = catalogue.parse_xccdf(XCCDF)
    mapping = {"CISC-RT-000010": {"condition": {"property": "REMOTE_ACCESS.TELNET_ENABLED", "operator": "EQUALS", "value": False}}}
    doc = catalogue.build("stig", entries, license_="DISA public domain", source="https://public.cyber.mil/stigs/", mapping=mapping)
    assert doc["_meta"] == {"framework": "STIG", "total": 2, "automated": 1}
    path = catalogue.write(doc, tmp_path)
    assert path.name == "imported_stig.yaml" and "licensed text" in path.read_text(encoding="utf-8")
    okf = okf_layer()
    kb = type(okf["ckb"])().load(tmp_path)
    assert {c.control_id for c in kb.all()} == {"STIG-CISC-RT-000010", "STIG-CISC-RT-000020"}
    eng = okf["ComplianceEngine"](kb.all(), {})
    res = {f.control_id: f.status for f in eng.evaluate({"REMOTE_ACCESS": {"TELNET_ENABLED": True}}, vendor="cisco", platform="ios_xe")}
    assert res["STIG-CISC-RT-000020"] == "UNKNOWN"                 # no automated check: could not be assessed, NOT compliant
    assert res["STIG-CISC-RT-000010"] in ("FAIL", "UNKNOWN")
    assert catalogue.coverage(tmp_path) == [{"file": "imported_stig.yaml", "total": 2, "automated": 1, "automated_pct": 50.0}]
    assert catalogue.coverage(tmp_path / "nope") == []


def test_build_validates_provenance_ids_and_duplicates():
    e = [{"id": "A-1", "title": "t", "severity": "LOW"}]
    with pytest.raises(catalogue.CatalogueError):
        catalogue.build("CIS", e, license_="", source="x")
    with pytest.raises(catalogue.CatalogueError):
        catalogue.build("CIS", e, license_="l", source="")
    with pytest.raises(catalogue.CatalogueError):
        catalogue.build("!!!", e, license_="l", source="s")
    with pytest.raises(catalogue.CatalogueError):
        catalogue.build("CIS", [{"id": "../etc", "title": "t", "severity": "LOW"}], license_="l", source="s")
    with pytest.raises(catalogue.CatalogueError):
        catalogue.build("CIS", e + e, license_="l", source="s")


def test_cli_catalogue_import_and_coverage(tmp_path, monkeypatch, capsys):
    f = tmp_path / "stig.xml"
    f.write_bytes(XCCDF)
    assert cli.main(["catalogue-import", str(f), "--framework", "STIG", "--license", "DISA public", "--source", "u", "--dry-run"]) == 0
    assert "2 controls, 0 with an automated check, 2 will report UNKNOWN" in capsys.readouterr().out
    monkeypatch.setattr(catalogue.cfg, "OKF_DIR", tmp_path)
    assert cli.main(["catalogue-import", str(f), "--framework", "STIG", "--license", "DISA public", "--source", "u"]) == 0
    assert (tmp_path / "knowledge" / "controls" / "imported_stig.yaml").exists()
    assert cli.main(["catalogue-coverage"]) == 0 and "0/2 automated" in capsys.readouterr().out
    bad = tmp_path / "bad.csv"
    bad.write_bytes(b"x,y\n1,2\n")
    assert cli.main(["catalogue-import", str(bad), "--framework", "CIS", "--license", "l", "--source", "s"]) == 1
    assert "error:" in capsys.readouterr().out
    mp = tmp_path / "map.yaml"
    mp.write_text("CISC-RT-000010:\n  condition: {property: REMOTE_ACCESS.TELNET_ENABLED, operator: EQUALS, value: false}\n", encoding="utf-8")
    assert cli.main(["catalogue-import", str(f), "--framework", "STIG", "--license", "l", "--source", "s", "--mapping", str(mp), "--dry-run"]) == 0
    assert "1 with an automated check" in capsys.readouterr().out
    monkeypatch.setattr(catalogue.cfg, "OKF_DIR", tmp_path / "empty")
    assert cli.main(["catalogue-coverage"]) == 0 and "no imported catalogues" in capsys.readouterr().out
