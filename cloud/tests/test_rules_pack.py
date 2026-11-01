import shutil
from pathlib import Path

import pytest
import yaml

from cloud.rules import pack as packmod
from cloud.rules.pack import PackError, default_pack_dir, load_pack

REAL = default_pack_dir()


def clone(tmp_path) -> Path:
    dst = tmp_path / "okf-cloud"
    shutil.copytree(REAL, dst, ignore=shutil.ignore_patterns("__pycache__"))
    return dst


def edit(base: Path, key: str, fn):
    f = next((base / "knowledge" / key).glob("*.yaml"))
    doc = yaml.safe_load(f.read_text(encoding="utf-8"))
    fn(doc[key])
    f.write_text(yaml.safe_dump(doc), encoding="utf-8")


def test_shipped_pack_loads_and_is_consistent():
    p = load_pack()
    assert p.version and len(p.controls) >= 25 and len(p.properties) >= 25
    ids = [c.id for c in p.controls]
    assert len(set(ids)) == len(ids) and all(i.startswith("CLOUD-") for i in ids)
    assert "aws_security_group" in p.by_type and "Pod" in p.by_type
    for c in p.controls:                                  # every control states how it handles unknowns and what to do
        assert c.remediation["summary"] and c.unknown_handling and c.logic_version
        assert all(fw["verified"] is False for fw in c.frameworks)      # nothing is claimed as verified yet
        assert not any(fw["framework"] == "CIS" for fw in c.frameworks)  # no invented benchmark IDs
    used = {p_ for c in p.controls for p_ in packmod.condition_properties(c.condition)}
    assert used <= set(p.properties)


def test_default_pack_dir_honours_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("CLOUD_OKF_DIR", str(tmp_path))
    assert default_pack_dir() == tmp_path
    monkeypatch.delenv("CLOUD_OKF_DIR")
    assert default_pack_dir().name == "okf-cloud"


def test_condition_properties_walks_all_and_any():
    cond = {"all": [{"property": "A"}, {"any": [{"property": "B"}, {"property": "C"}]}]}
    assert packmod.condition_properties(cond) == ["A", "B", "C"]
    assert packmod.condition_properties({}) == []


@pytest.mark.parametrize("mutate,needle", [
    (lambda c: c[0].update(severity="SEVERE"), "invalid severity"),
    (lambda c: c[0].update(id="NET-001"), "must start with CLOUD-"),
    (lambda c: c.append(dict(c[0])), "unique"),
    (lambda c: c[0].update(condition={"property": "NOPE", "operator": "EQUALS", "value": 1}), "unknown property"),
    (lambda c: c[0].update(condition={"property": "NET.SG.PUBLIC_SSH_V4", "operator": "WITHIN"}), "unknown operator"),
    (lambda c: c[0].update(condition="not-a-mapping"), "condition must be a mapping"),
    (lambda c: c[0].update(remediation={}), "remediation.summary"),
    (lambda c: c[0].pop("name"), "name is required"),
    (lambda c: c[0].update(frameworks=[{"framework": "NIST-800-53", "control_id": "SC-7"}]), "boolean 'verified'"),
    (lambda c: c[0].update(frameworks=[{"framework": "CIS", "control_id": "1.1", "verified": False}]), "licensed edition"),
    (lambda c: c[0].update(condition={"all": [{"property": "NOPE"}]}), "unknown property"),
])
def test_invalid_controls_are_refused(tmp_path, mutate, needle):
    base = clone(tmp_path)
    edit(base, "controls", mutate)
    with pytest.raises(PackError, match=needle):
        load_pack(base)


def test_verified_cis_mapping_is_allowed(tmp_path):
    base = clone(tmp_path)
    edit(base, "controls", lambda c: c[0].update(frameworks=[{"framework": "CIS", "control_id": "x", "verified": True}]))
    assert load_pack(base).controls[0].frameworks[0]["framework"] == "CIS"


@pytest.mark.parametrize("mutate,needle", [
    (lambda m: m[0].update(extractors=["nope"]), "unknown extractor"),
    (lambda m: m[0].pop("id"), "id and resource_types are required"),
    (lambda m: m[0].update(properties={"NOPE.PROP": {"paths": ["a"]}}), "unknown property"),
    (lambda m: m[0].update(properties={"NET.SG.PUBLIC_RDP": {"op": "eq"}}), "paths or all_true"),
    (lambda m: m[0].update(properties={"NET.SG.PUBLIC_RDP": {"paths": ["a"], "op": "wat"}}), "unknown op"),
    (lambda m: m[0].update(properties={"NET.SG.PUBLIC_RDP": "scalar"}), "paths or all_true"),
])
def test_invalid_mappings_are_refused(tmp_path, mutate, needle):
    base = clone(tmp_path)
    edit(base, "mappings", mutate)
    with pytest.raises(PackError, match=needle):
        load_pack(base)


@pytest.mark.parametrize("mutate,needle", [
    (lambda p: p[0].update(type="blob"), "type must be one of"),
    (lambda p: p.append(dict(p[0])), "duplicate"),
    (lambda p: p[0].pop("id"), "missing or duplicate"),
])
def test_invalid_properties_are_refused(tmp_path, mutate, needle):
    base = clone(tmp_path)
    edit(base, "properties", mutate)
    with pytest.raises(PackError, match=needle):
        load_pack(base)


def test_empty_pack_directory_is_handled(tmp_path):
    base = tmp_path / "okf-cloud"
    for key in ("properties", "mappings", "controls"):
        (base / "knowledge" / key).mkdir(parents=True)
    (base / "okf_manifest.yaml").write_text("", encoding="utf-8")
    p = load_pack(base)
    assert p.controls == [] and p.version == "0"
