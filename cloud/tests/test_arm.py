import json

from cloud import pipeline
from cloud.ir import Unknown
from cloud.parsers.arm import MAX_DEPTH, parse_arm

TEMPLATE = json.dumps({
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "parameters": {"sku": {"type": "string", "defaultValue": "Standard_LRS"}, "calc": {"defaultValue": "[concat('a','b')]"},
                   "nodefault": {"type": "string"}},
    "variables": {"tls": "TLS1_2", "dyn": "[uniqueString('x')]"},
    "resources": [
        {"type": "Microsoft.Storage/storageAccounts", "apiVersion": "2022-09-01", "name": "[parameters('nodefault')]",
         "sku": {"name": "[parameters('sku')]"}, "properties": {"minimumTlsVersion": "[variables('tls')]", "x": "[variables('dyn')]",
                                                             "lit": "[[escaped]", "y": "[parameters('calc')]", "z": "[parameters('missing')]"},
         "copy": {"name": "c", "count": 2}, "condition": "[true()]"},
        {"type": "Microsoft.Network/networkSecurityGroups", "name": "nsg", "properties": {"securityRules": []},
         "resources": [{"type": "securityRules", "name": "r1", "properties": {}}, {"type": "securityRules", "name": "r1"}, "oops", {"name": "x"}]},
        {"type": "Microsoft.Storage/storageAccounts", "name": "[parameters('nodefault')]"}]})


def test_arm_resources_params_nested_and_unresolved():
    r = parse_arm("t.json", TEMPLATE)
    types = [x.resource_type for x in r.resources]
    assert types == ["Microsoft.Storage/storageAccounts", "Microsoft.Network/networkSecurityGroups",
                     "Microsoft.Network/networkSecurityGroups/securityRules", "Microsoft.Network/networkSecurityGroups/securityRules",
                     "Microsoft.Storage/storageAccounts"]
    st = r.resources[0]
    assert st.properties["sku"]["name"] == "Standard_LRS" and st.properties["properties"]["minimumTlsVersion"] == "TLS1_2"
    assert st.properties["properties"]["lit"] == "[escaped]"
    for k in ("x", "y", "z"):
        assert isinstance(st.properties["properties"][k], Unknown)
    assert isinstance(st.properties["name"], Unknown) and len(st.notes) == 2 and st.source.line_start >= 1
    assert r.resources[2].address.endswith("nsg/r1") and r.resources[3].address.endswith("#2")
    assert r.resources[4].address.endswith("(dynamic)#2")
    assert r.errors == [{"file": "t.json", "error": "resource without a type"}]


def test_arm_errors_symbolic_names_depth_and_limits(monkeypatch):
    assert "invalid JSON" in parse_arm("a.json", "{").errors[0]["error"]
    assert "invalid JSON" in parse_arm("a.json", "[" * 100000).errors[0]["error"]
    assert "no resources" in parse_arm("a.json", "[]").errors[0]["error"]
    sym = parse_arm("a.json", json.dumps({"resources": {"s": {"type": "A/b", "name": "n"}}}))
    assert [x.resource_type for x in sym.resources] == ["A/b"]
    deep = {"type": "A/b", "name": "n", "properties": {}}
    node = deep["properties"]
    for _ in range(MAX_DEPTH + 5):
        node["k"] = {}
        node = node["k"]
    d = parse_arm("a.json", json.dumps({"resources": [deep]}))
    assert "Unknown" in repr(d.resources[0].properties) and d.resources[0].unknown_fields
    monkeypatch.setattr("cloud.parsers.arm.MAX_RESOURCES", 1)
    t = parse_arm("a.json", json.dumps({"resources": [{"type": "A/b", "name": "1"}, {"type": "A/b", "name": "2"}]}))
    assert len(t.resources) == 1 and t.truncated
    assert parse_arm("a.json", json.dumps({"resources": [{"type": "A/b"}]})).resources[0].logical_name == "(dynamic)"


def test_arm_through_the_pipeline_and_bicep_is_unsupported(tmp_path):
    nsg = json.dumps({"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#", "resources": [
        {"type": "Microsoft.Network/networkSecurityGroups", "name": "n", "properties": {"securityRules": [{"properties": {
            "access": "Allow", "direction": "Inbound", "protocol": "Tcp", "sourceAddressPrefix": "*", "destinationPortRange": "22"}}]}}]})
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a/azuredeploy.json", nsg)
        zf.writestr("a/main.bicep", "resource x 'Microsoft.Storage/storageAccounts@2022-09-01' = {}")
    rep = pipeline.run_scan(buf.getvalue(), "a.zip", tmp_path, salt=b"s")
    assert any(f["control_id"] == "CLOUD-NET-001" and f["evidence_state"] == "FAIL_STATIC" for f in rep["findings"])
    assert rep["coverage"]["unsupported_formats"].get("bicep") == 1


def test_line_lookup_falls_back_when_the_type_text_is_escaped_or_absent():
    from cloud.parsers.arm import _line_of
    assert _line_of("a" + chr(10) + "b é", "é", 0)[0] == 2
    assert _line_of("abc", "zz", 0) == (1, 0)
