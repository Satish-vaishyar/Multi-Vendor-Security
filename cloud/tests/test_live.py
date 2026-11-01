import json
import logging
import pickle
from datetime import datetime, timedelta, timezone

import pytest

from cloud import live
from cloud.live import Authorization, LiveRefused, ReadOnlyGuard, Secret, reconcile

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def auth(**kw):
    base = dict(org_id="o", provider="aws", scope="123", role_ref="arn:role/ro", authorised_by="ciso", expires_at=NOW + timedelta(days=30),
                read_only_attested=True)
    return Authorization(**{**base, **kw})


def test_guard_allows_metadata_reads_only():
    g = ReadOnlyGuard("aws")
    assert g.check(" DescribeSecurityGroups ") == "DescribeSecurityGroups" and g.check("ListBuckets") == "ListBuckets"
    for bad in ("PutBucketPolicy", "DeleteSecurityGroup", "RunInstances", "", "  ", "GetSecretValue", "GetObject", "GetParameters",
                "GetPasswordData", "ListAccessKeys", "GetSessionToken", "DescribeDecryptKeys"):
        with pytest.raises(LiveRefused):
            g.check(bad)
    assert ReadOnlyGuard("azure").check("GET") == "GET"
    with pytest.raises(LiveRefused):
        ReadOnlyGuard("azure").check("PUT")
    assert ReadOnlyGuard("gcp").check("getIamPolicy") and ReadOnlyGuard("oci").check("listVcns")
    with pytest.raises(LiveRefused):
        ReadOnlyGuard("alibaba")


def test_authorization_rules():
    assert auth().require(NOW).org_id == "o"
    for kw, fragment in ((dict(scope=""), "scope"), (dict(provider="x"), "unsupported"), (dict(read_only_attested=False), "read-only"),
                         (dict(expires_at=NOW - timedelta(days=1)), "expired"), (dict(expires_at=datetime(2030, 1, 1)), "timezone"),
                         (dict(expires_at=NOW + timedelta(days=400)), "at most 90")):
        with pytest.raises(LiveRefused, match=fragment):
            auth(**kw).require(NOW)
    assert auth().problems() != []                                  # the real clock: the fixed 2026-01 expiry has passed or is checked live


def test_secret_never_leaks_by_accident(caplog):
    s = Secret("hunter2-very-secret")
    with caplog.at_level(logging.INFO):
        logging.getLogger("x").info("creds %s %r %s", s, s, f"{s}")
    assert "hunter2" not in caplog.text and "hunter2" not in repr(s) + str(s) + format(s, ">20")
    assert s.reveal() == "hunter2-very-secret" and s != s and s != "hunter2-very-secret"
    with pytest.raises(TypeError):
        json.dumps({"k": s})
    with pytest.raises(TypeError):
        pickle.dumps(s)
    with pytest.raises(AttributeError):
        s.x = 1
    with pytest.raises(TypeError):
        hash(s)


def f(cid, state, res="r", **kw):
    return {"control_id": cid, "resource_address": res, "evidence_state": state, **kw}


def test_reconcile_confirms_conflicts_and_never_upgrades_unknown_to_pass():
    static = [f("A", "FAIL_STATIC"), f("B", "PASS_STATIC"), f("C", "FAIL_STATIC"), f("D", "PASS_STATIC"), f("E", "UNKNOWN_STATIC"),
              f("F", "UNKNOWN_STATIC"), f("G", "FAIL_STATIC"), f("H", "PASS_STATIC", notes=["n"]), f("I", "FAIL_STATIC")]
    liv = [f("A", "FAIL_LIVE"), f("B", "FAIL_LIVE"), f("C", "PASS_LIVE"), f("D", "PASS_LIVE"), f("E", "PASS_LIVE"), f("F", "FAIL_LIVE"),
           f("G", "UNKNOWN_LIVE"), f("Z", "FAIL_LIVE", res="only-live")]
    out = {(x["control_id"], x["resource_address"]): x for x in reconcile(static, liv)}
    assert [out[(c, "r")]["evidence_state"] for c in "ABCDEFGH"] == ["FAIL_LIVE", "CONFLICT", "CONFLICT", "PASS_LIVE", "PASS_LIVE",
                                                                    "FAIL_LIVE", "FAIL_STATIC", "PASS_STATIC"]
    assert out[("I", "r")]["evidence_state"] == "FAIL_STATIC" and "notes" in out[("I", "r")]
    assert "static analysis says PASS_STATIC" in out[("B", "r")]["notes"][0]
    assert "live evidence unavailable" in out[("G", "r")]["notes"][0] and out[("H", "r")]["notes"] == ["n"]
    assert out[("Z", "only-live")]["evidence_state"] == "FAIL_LIVE" and len(out) == 10
    assert live.MAX_AUTH_DAYS == 90
