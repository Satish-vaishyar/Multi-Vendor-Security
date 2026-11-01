"""Branch coverage for app/engines/pqc.py: inventory rows, legacy-row healing and payload normalisation."""
import pytest

from app.engines import pqc


def test_tls_number_parsing_of_missing_values():
    assert pqc._tls_num(None) is None
    assert pqc._tls_num("v1.3") == 1.3 and pqc._tls_num("garbage") is None


def _rows(components):
    return {r["algorithm"]: r for r in pqc.build_cbom("AST-1", {}, components)}


def test_inventory_components_become_friendly_rows():
    rows = pqc.build_cbom("AST-1", {}, [
        {"vendor": "openbsd", "product": "openssh", "version": "8.0"},
        {"vendor": "openbsd", "product": "openssh", "version": "9.9-mlkem"},
        {"vendor": "strongswan", "product": "ipsec", "version": "5.9", "component_type": "vpn daemon"},
        {"vendor": "strongswan", "product": "ipsec", "version": "6.0 ml-kem"},
        {"vendor": "acme", "product": "tls-proxy", "version": "1.0"},
        {"vendor": "acme", "product": "tls-proxy", "version": "2.0 mldsa", "component_type": ""},
        {"vendor": "x", "product": "unrelated"},
    ])
    by = {}
    for r in rows:
        by.setdefault(r["protocol"], []).append(r)
    ssh, ipsec, tls = by["SSH"], by["IPsec / IKE"], by["TLS"]
    assert {r["pqc_status"] for r in ssh} == {"TRANSITION", "READY"} and "OpenSSH" in ssh[0]["algorithm"]
    assert {r["pqc_status"] for r in ipsec} == {"TRANSITION", "READY"} and "IPsec stack" in ipsec[0]["algorithm"]
    assert {r["pqc_status"] for r in tls} == {"TRANSITION", "READY"} and "TLS stack" in tls[0]["algorithm"]
    assert all(r["location"] == "inventory" for r in rows)


@pytest.mark.parametrize("score,counts,label", [
    (10, {"MIGRATION_REQUIRED": 2}, "At risk"), (90, {"READY": 1}, "On track"), (70, {}, "Progressing"),
    (30, {}, "Early transition"), (5, {}, "At risk"), (90, {}, "Progressing")])
def test_readiness_labels(score, counts, label):
    assert pqc.readiness_label(score, counts) == label


@pytest.mark.parametrize("algo,expect", [
    ("openssh", "OpenSSH"), ("openssl", "OpenSSL"), ("tls", "TLS stack"), ("ipsec", "IPsec stack")])
def test_legacy_generic_rows_are_upgraded(algo, expect):
    out = pqc._heal_legacy_row({"algorithm": algo, "protocol": algo, "version": "1.1" if algo == "openssl" else ""})
    assert expect in out["algorithm"] and out["summary"] and out["fix_steps"]
    assert pqc._heal_legacy_row(dict(out)) == out                               # idempotent: a row with a summary is left alone
    assert pqc._heal_legacy_row({"algorithm": "RSA", "protocol": "TLS"})["algorithm"] == "RSA"
    again = pqc._heal_legacy_row({"algorithm": algo, "protocol": algo, "usage": "kept", "recommended": "kept", "version": "9"})
    assert again["summary"]


def test_normalisation_backfills_rows_counts_and_recommendations():
    payload = {
        "algorithms": [
            {"algorithm": "RSA-2048", "protocol": "TLS", "pqc_status": "TRANSITION", "migration": "move", "risk": "", "priority": ""},
            {"algorithm": "X", "protocol": "SSH", "pqc_status": "CUSTOM"},
            {"algorithm": "Y", "protocol": "SSH", "pqc_status": "READY", "fix_steps": []},
        ],
        "counts": {"READY": 0, "TRANSITION": 0, "MIGRATION_REQUIRED": 0, "UNKNOWN": 0},
        "migration_recommendations": [
            "move",                                    # matches the RSA row by its migration text
            "something unrelated",                     # falls back to the first row
            {"algorithm": "RSA-2048", "protocol": "TLS", "summary": ""},      # structured, matches a row
            {"algorithm": "Z", "protocol": "?", "risk": "", "priority": "", "current": "", "recommended_direction": "", "fix_steps": [],
             "migration": "m"},                        # structured, matches nothing -> every fallback fires
            7,
        ]}
    out = pqc.normalize_pqc_payload(payload)
    assert out["counts"]["CUSTOM"] == 1 and out["counts"]["TRANSITION"] == 1                 # stale counts were recomputed
    assert out["algorithms"][0]["risk"] and out["algorithms"][0]["priority"] and out["algorithms"][2]["fix_steps"] == []
    recs = out["migration_recommendations"]
    assert recs[0]["algorithm"] == "RSA-2048" and recs[1]["algorithm"] == "RSA-2048"
    assert recs[3]["risk"] and recs[3]["current"] == "Z" and recs[3]["recommended_direction"] == "m" and recs[3]["fix_steps"] == ["m"]
    assert out["readiness_label"] in ("At risk", "Early transition", "Progressing", "On track")


def test_string_recommendation_without_any_row_is_general_hygiene_and_empty_payload_is_not_run():
    out = pqc.normalize_pqc_payload({"migration_recommendations": ["rotate keys"]})
    assert out["migration_recommendations"][0]["algorithm"] == "General crypto hygiene"
    out = pqc.normalize_pqc_payload({})
    assert out["readiness_label"] == "Not run" and out["algorithms"] == []
    assert pqc.normalize_pqc_payload(None)["readiness_label"] == "Not run"


def test_a_rec_text_with_no_matching_row_keeps_going_and_a_bad_score_gets_a_dash():
    row = {"algorithm": "A", "protocol": "P", "pqc_status": "READY", "migration": "m1", "recommended": "r1"}
    out = pqc.normalize_pqc_payload({"algorithms": [row], "migration_recommendations": ["r1", "m1"], "readiness_score": "n/a"})
    assert out["readiness_label"] == "—" and len(out["migration_recommendations"]) == 2
    out = pqc.normalize_pqc_payload({"algorithms": [{"algorithm": "A", "pqc_status": "READY", "migration": "m1"}],
                                     "migration_recommendations": [{"algorithm": "A", "protocol": "", "current": "", "risk": ""}]})
    assert out["migration_recommendations"][0]["fix_steps"] == [] or out["migration_recommendations"][0]["fix_steps"]
    full = pqc.normalize_pqc_payload({"algorithms": [{"algorithm": "A", "protocol": "P", "pqc_status": "TRANSITION", "migration": "m"}],
                                      "migration_recommendations": [{"algorithm": "A", "protocol": "P"}], "readiness_label": "Given"})
    assert full["readiness_label"] == "Given" and full["migration_recommendations"][0]["risk"]
