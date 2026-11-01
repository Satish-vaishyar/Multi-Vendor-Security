from cloud.ir import Resource, Source, Unknown
from cloud.parsers.terraform import parse_terraform
from cloud.rules import extractors as ex


def res(rtype, props):
    return Resource("x", "", rtype, "r", f"{rtype}.r", props, Source("f", 1, 1))


def net(text):
    return ex.network_ingress(parse_terraform([("main.tf", text)]).resources[0])


def nsg(extra):
    return net('resource "azurerm_network_security_rule" "r" {\n%s\n}\n' % extra)["NET.SG.PUBLIC_SSH_V4"]


def test_unknown_or_missing_azure_access_and_direction_are_unknown_not_no_rule():
    assert nsg('  access = var.a\n  direction = "Inbound"\n  source_address_prefix = "*"\n  destination_port_range = "22"') is None
    assert nsg('  access = "Allow"\n  source_address_prefix = "*"\n  destination_port_range = "22"') is None
    assert nsg('  access = "Allow"\n  direction = var.d\n  source_address_prefix = "*"\n  destination_port_range = "22"') is None
    group = net('resource "azurerm_network_security_group" "g" {\n  security_rule {\n    access = "Allow"\n    source_address_prefix = "*"\n  }\n}\n')
    assert group["NET.SG.PUBLIC_SSH_V4"] is None
    arm = res("Microsoft.Network/networkSecurityGroups",
              {"properties": {"securityRules": [{"properties": {"access": Unknown("x"), "direction": "Inbound"}}]}})
    assert ex.network_ingress(arm)["NET.SG.PUBLIC_SSH_V4"] is None
    assert nsg('  access = "Deny"\n  direction = "Inbound"\n  source_address_prefix = "*"\n  destination_port_range = "22"') is False


def test_unknown_or_missing_oci_direction_is_unknown():
    def oci(extra):
        return ex.network_ingress(res("oci_core_network_security_group_security_rule", {"protocol": "6", "source": "0.0.0.0/0", **extra}))
    assert oci({})["NET.SG.PUBLIC_SSH_V4"] is None and oci({"direction": Unknown("v")})["NET.SG.PUBLIC_SSH_V4"] is None
    assert oci({"direction": "EGRESS"})["NET.SG.PUBLIC_SSH_V4"] is False and oci({"direction": "INGRESS"})["NET.SG.PUBLIC_SSH_V4"] is True
