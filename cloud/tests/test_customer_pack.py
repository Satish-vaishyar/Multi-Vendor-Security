import pytest

from cloud import pipeline
from cloud.rules.customer import ENV_VAR, MAX_CONTROLS, extend_pack, load_effective_pack
from cloud.rules.pack import PackError, load_pack

GOOD = '''controls:
  - id: CUSTOM-NO-LATEST
    name: Images must be pinned (house rule)
    category: supply_chain
    severity: HIGH
    logic_version: "1"
    condition: {property: K8S.CONTAINER.IMAGE_UNPINNED, operator: EQUALS, value: false}
    frameworks: [{framework: ISO27001, control_id: A.8.9, verified: false}]
    remediation: {summary: "Pin the image by digest."}
'''
POD = "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: d}\nspec:\n  containers:\n    - name: a\n      image: nginx:latest\n"


def make(tmp_path, controls=None, policy=None):
    (tmp_path / "controls").mkdir()
    if controls is not None:
        (tmp_path / "controls" / "c.yaml").write_text(controls, encoding="utf-8")
    if policy is not None:
        (tmp_path / "policy.yaml").write_text(policy, encoding="utf-8")
    return tmp_path


def test_private_pack_adds_a_control_without_code_and_is_reported(tmp_path):
    pack = extend_pack(load_pack(), make(tmp_path, GOOD))
    assert "CUSTOM-NO-LATEST" in {c.id for c in pack.controls} and pack.version.endswith("+customer")
    rep = pipeline.run_scan(POD.encode(), "pod.yaml", tmp_path / "w", pack=pack, salt=b"s")
    assert any(f["control_id"] == "CUSTOM-NO-LATEST" and f["evidence_state"] == "FAIL_STATIC" for f in rep["findings"])
    assert rep["coverage"]["rule_pack_customisations"] == ["added 1 customer control(s)"]


def test_severity_override_and_justified_disable_are_always_reported(tmp_path):
    pol = 'severity: {CLOUD-K8S-001: LOW}\ndisable: {CLOUD-K8S-005: "Host networking is required by the node agent, reviewed 2026"}\n'
    pack = extend_pack(load_pack(), make(tmp_path, None, pol))
    by = {c.id: c for c in pack.controls}
    assert by["CLOUD-K8S-001"].severity == "LOW" and "CLOUD-K8S-005" not in by
    assert len(pack.customisations) == 2 and "disabled by the organisation" in pack.customisations[1]


@pytest.mark.parametrize("controls,policy,fragment", [
    (GOOD.replace("CUSTOM-NO-LATEST", "CLOUD-NET-001"), None, "id must match"),
    (GOOD.replace("HIGH", "SUPER"), None, "invalid severity"),
    (GOOD.replace("K8S.CONTAINER.IMAGE_UNPINNED", "NOPE.PROP"), None, "unknown property"),
    (GOOD.replace("verified: false", "verified: true"), None, "verified: false"),
    (GOOD.replace("remediation: {summary: \"Pin the image by digest.\"}", "remediation: {}"), None, "remediation.summary"),
    (GOOD + "  - oops\n", None, "must be a mapping"),
    (GOOD.replace('name: Images must be pinned (house rule)', "name: ''"), None, 'name is required'),
    (GOOD.replace("logic_version: \"1\"", "logic_version: \"1\"\n    extractors: [evil]"), None, "unsupported keys"),
    ("controls: []\nmappings: []\n", None, "cannot add code"),
    ("- not a mapping\n", None, "must be a mapping"),
    ("{unclosed", None, "unreadable"),
    (None, "severity: {CUSTOM-X: LOW}", "built-in control"),
    (None, "severity: {CLOUD-K8S-001: SUPER}", "built-in control"),
    (None, "disable: {CLOUD-K8S-001: short}", "justification"),
    (None, "disable: {NOPE: 'a long enough justification text'}", "not a built-in"),
    (None, "extra: 1", "unsupported keys"),
])
def test_invalid_customer_packs_do_not_load(tmp_path, controls, policy, fragment):
    with pytest.raises(PackError) as e:
        extend_pack(load_pack(), make(tmp_path, controls, policy))
    assert fragment in str(e.value)


def test_limits_and_environment_switch(tmp_path, monkeypatch):
    big = tmp_path / "big"
    (big / "controls").mkdir(parents=True)
    (big / "controls" / "c.yaml").write_text("#" * (1024 * 1024 + 1), encoding="utf-8")
    with pytest.raises(PackError, match="larger than"):
        extend_pack(load_pack(), big)
    many = tmp_path / "many"
    (many / "controls").mkdir(parents=True)
    for i in range(51):
        (many / "controls" / f"{i}.yaml").write_text("controls: []\n", encoding="utf-8")
    with pytest.raises(PackError, match="more than 50"):
        extend_pack(load_pack(), many)
    body = "controls:\n" + "".join(GOOD.split("\n", 1)[1].replace("CUSTOM-NO-LATEST", f"CUSTOM-N{i}") for i in range(MAX_CONTROLS + 1))
    over = tmp_path / "over"
    (over / "controls").mkdir(parents=True)
    (over / "controls" / "c.yaml").write_text(body, encoding="utf-8")
    with pytest.raises(PackError, match="more than 200"):
        extend_pack(load_pack(), over)
    assert extend_pack(load_pack(), tmp_path / "missing").customisations == []
    assert load_effective_pack(env={}).customisations == []
    d = make(tmp_path / "e", None) if (tmp_path / "e").mkdir() is None else None
    (d / "controls" / "c.yaml").write_text(GOOD, encoding="utf-8")
    assert "CUSTOM-NO-LATEST" in {c.id for c in load_effective_pack(env={ENV_VAR: str(d)}).controls}
