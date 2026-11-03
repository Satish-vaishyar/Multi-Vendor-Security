"""Regression tests built on real misconfigured/hardened files (cloud/fixtures); found by the independent verification."""
from pathlib import Path

import pytest

from cloud import pipeline
from cloud.rules.extractors import _netpol_rule_allows_all
from cloud import secret_scan as s

FIX = Path(__file__).resolve().parents[1] / "fixtures"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG" + "bPxRfiCYQwErTyUiOpA"


def scan(rel, tmp_path):
    return pipeline.run_scan((FIX / rel).read_bytes(), Path(rel).name, tmp_path, salt=b"fixed-salt")


def state(report, control):
    got = {f["evidence_state"] for f in report["findings"] if f["control_id"] == control}
    return got


def test_every_fixture_scans_to_completion(tmp_path):
    for path in sorted(FIX.rglob("*")):
        if path.is_file() and path.suffix in {".tf", ".yaml", ".json"}:
            rel = path.relative_to(FIX).as_posix()
            wd = tmp_path / rel.replace("/", "_")
            wd.mkdir()
            rep = scan(rel, wd)
            assert rep["status"] == "COMPLETED", rel
            stmt = rep["statement"].lower()
            assert not any(w in stmt for w in ("compliant", "certified", "fully secure", "is secure")), rel


def test_allow_all_netpol_via_empty_namespace_selector_is_detected(tmp_path):
    assert state(scan("vuln/netpol-nsselector.yaml", tmp_path), "CLOUD-K8S-008") == {"FAIL_STATIC"}


def test_literal_empty_rule_netpol_is_still_detected(tmp_path):
    assert state(scan("vuln/netpol-allowall.yaml", tmp_path), "CLOUD-K8S-008") == {"FAIL_STATIC"}


def test_port_scoped_netpol_is_not_a_violation(tmp_path):
    assert state(scan("secure/netpol-port-scoped.yaml", tmp_path), "CLOUD-K8S-008") == {"PASS_STATIC"}


@pytest.mark.parametrize("rule,expected", [
    ({}, True),
    ({"from": []}, True),
    ({"ports": []}, True),
    ({"to": None}, True),
    ({"from": [{}]}, True),
    ({"from": [{"namespaceSelector": {}}]}, True),
    ({"to": [{"podSelector": {}}]}, True),
    ({"from": [{"namespaceSelector": {}}], "ports": [{"port": 80}]}, False),
    ({"from": [{"namespaceSelector": {"matchLabels": {"a": "b"}}}]}, False),
    ({"from": [{"ipBlock": {"cidr": "10.0.0.0/8"}}]}, False),
    ("junk", False),
])
def test_netpol_rule_allows_all_forms(rule, expected):
    assert _netpol_rule_allows_all(rule) is expected


def test_cloud_init_users_passwd_is_detected(tmp_path):
    assert state(scan("vuln/cloud-init-passwd.yaml", tmp_path), "CLOUD-INIT-002") == {"FAIL_STATIC"}


def test_cloud_init_plain_text_passwd_is_still_detected(tmp_path):
    assert state(scan("vuln/cloud-init-plain.yaml", tmp_path), "CLOUD-INIT-002") == {"FAIL_STATIC"}


def test_http_tokens_is_not_a_secret(tmp_path):
    rep = scan("secure/main.tf", tmp_path)
    assert not [f for f in rep["findings"] if f["control_id"] == "CLOUD-SEC-001"]
    assert not [f for f in rep["findings"] if f["evidence_state"] == "FAIL_STATIC"]


def test_http_tokens_allow_list_does_not_hide_real_secrets():
    kinds = lambda t: {f.rule_id for f in s.scan_text("x.tf", t, b"salt")}
    assert kinds('http_tokens = "required"') == set()
    assert kinds('api_token = "Zx9!qLm2Vb7#Rt4Hs8"') == {"SEC-GENERIC"}
    assert kinds('password = "Zx9!qLm2Vb7#Rt4Hs8"') == {"SEC-GENERIC"}
    assert s._generic_key_allowed("not a key at all =") is False


def test_aws_secret_never_leaks_into_the_report(tmp_path):
    tf = 'resource "aws_instance" "w" {\n  user_data = "export AWS_SECRET_ACCESS_KEY=%s"\n}\n' % AWS_SECRET
    rep = pipeline.run_scan(tf.encode(), "secret.tf", tmp_path, salt=b"fixed-salt")
    assert "CLOUD-SEC-001" in {f["control_id"] for f in rep["findings"]}
    assert AWS_SECRET not in str(rep)


def test_unresolvable_value_is_unknown_not_pass(tmp_path):
    states = state(scan("unknown/volume.tf", tmp_path), "CLOUD-STO-002")
    assert states == {"UNKNOWN_STATIC"}


def test_manifest_matches_the_loaded_pack():
    import yaml
    from cloud.rules.pack import default_pack_dir, load_pack
    manifest = yaml.safe_load((default_pack_dir() / "okf_manifest.yaml").read_text(encoding="utf-8"))
    pack = load_pack()
    assert manifest["properties_count"] == len(pack.properties)
    assert manifest["controls_count"] == len(pack.controls)
    assert manifest["control_packs"]["core"]["mappings"] == len(pack.mappings)
    assert {f["id"] for f in manifest["frameworks"]} == {f["framework"] for c in pack.controls for f in c.frameworks}
    assert not set(manifest["evidence_states"]) & set(manifest["reserved_evidence_states"])


def test_unruled_platform_is_reported_as_not_assessed(tmp_path):
    tf = 'resource "vsphere_virtual_machine" "vm" {\n  name = "x"\n}\n'
    rep = pipeline.run_scan(tf.encode(), "vm.tf", tmp_path, salt=b"fixed-salt")
    assert "vmware" in rep["coverage"]["providers"]
    assert any(x.startswith("vmware:") for x in rep["coverage"]["not_assessed"])


def test_ruled_platform_is_not_listed_as_unassessed(tmp_path):
    rep = scan("secure/main.tf", tmp_path)
    assert not any(": recognised" in x for x in rep["coverage"]["not_assessed"])


def test_cloud_init_hashed_passwd_is_not_clear_text(tmp_path):
    y = '#cloud-config\nusers:\n  - name: d\n    passwd: "$6$rounds=4056$saltsalt$H4shValu3NotPl4int3xt00"\nssh_pwauth: false\n'
    rep = pipeline.run_scan(y.encode(), "ci.yaml", tmp_path, salt=b"fixed-salt")
    assert state(rep, "CLOUD-INIT-002") == {"PASS_STATIC"}


def test_token_setting_names_are_not_secrets():
    kinds = lambda t: {f.rule_id for f in s.scan_text("x.tf", t, b"salt")}
    assert kinds('id_token_audience = "openid-connect"\nsession_token_ttl = "15-minutes"') == set()
    assert kinds('http_tokens = "optional"') == set()
    assert kinds('auth_token = "Zx9!qLm2Vb7#Rt4Hs8"') == {"SEC-GENERIC"}


def test_crypt_hash_is_not_a_clear_text_secret_but_plaintext_next_to_it_is():
    kinds = lambda t: {f.rule_id for f in s.scan_text("x.yaml", t, b"salt")}
    assert kinds('passwd: "$6$rounds=4056$saltsalt$H4shValu3NotPl4int3xt00"') == set()
    assert kinds('passwd: "Sup3rS3cret!Pass"') == {"SEC-GENERIC"}
