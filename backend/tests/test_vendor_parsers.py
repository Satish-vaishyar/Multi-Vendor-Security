"""Ground-truth tests for the structured vendor parsers.

Each corpus config (okf/tests/corpus/*.cfg) was written from vendor syntax documentation and every
expectation below was verified by reading the config line by line - they are NOT copied from parser
output. They lock behaviour and prove the parsers read evidence from the right lines.

LIMITATION (stated plainly): the corpus is authored, not captured from customer devices. Accuracy on
real-world configs must still be measured on real data (see docs/product_readiness_gaps.md P1-2).
"""
import random
import string
import time
from pathlib import Path

import pytest

from app.core import config as cfg
from app.services import integration

integration._ensure_bridge()
from src import vendor_parsers  # noqa: E402
from src.vendor_parsers import fingerprint  # noqa: E402

CORPUS = Path(cfg.OKF_DIR) / "tests" / "corpus"

# property -> expected value, or (value, basis) when the basis matters ("config" = read from a line,
# "default" = documented platform default assumed).
EXPECTED = {
    "cisco_iosxe_branch_insecure.cfg": ("cisco", "ios-xe", {
        "TELNET.ENABLED": (True, "config"),             # line vty 0 4 / transport input all
        "HTTP.ENABLED": (True, "config"), "HTTPS.ENABLED": True,
        "SSH.VERSION": 2, "SSH.RETRIES_LIMITED": False,  # authentication-retries 5
        "SSH.TIMEOUT_SET": True,
        "SNMP.COMMUNITY_PUBLIC": True, "SNMP.READWRITE": True, "SNMP.ACL_RESTRICTED": False, "SNMP.VERSION": 2,
        "SERVICE.PASSWORD_ENCRYPTION": (True, "config"),
        "PASSWORD.ENCRYPTED": False,                     # `enable password Cisco123`, `username admin ... password 0`
        "KEY.STORED_SECURE": False, "USER.DEFAULT_ACCOUNTS": True,
        "CRYPTO.WEAK_ALGO": True,                        # `secret 5 $1$...` (MD5-crypt)
        "ACL.PERMIT_ANY": (True, "config"),              # permit ip any any
        "AAA.AUTHENTICATION": (True, "config"), "AAA.ACCOUNTING": (False, "default"),
        "AAA.TACACS_CONFIGURED": (False, "default"),
        "LOGGING.ENABLED": True, "LOGGING.REMOTE_SERVER": True, "LOGGING.TIMESTAMPS": True,
        "NTP.ENABLED": True, "NTP.AUTHENTICATED": False,
        "VTY.ACL_APPLIED": False, "VTY.TIMEOUT_SET": False,  # exec-timeout 0 0
        "CONSOLE.SECURED": False, "AUX.DISABLED": False,
        "ROUTING.OSPF_AUTH": False, "ROUTING.BGP_AUTH": False, "ROUTING.AUTH_ENABLED": False,
        "BANNER.MOTD_SET": (True, "config"), "BANNER.LOGIN_SET": (False, "default"),
        "DNS.LOOKUP_DISABLED": (True, "config"),
        "IP.SOURCE_ROUTE_DISABLED": (False, "default"), "IP.REDIRECTS_DISABLED": False,
        "MONITORING.NETFLOW": (False, "default"), "DOS.PROTECTION": (True, "config"),
        "MGMT.ENCRYPTED_ONLY": False,
    }),
    "cisco_iosxe_core_hardened.cfg": ("cisco", "ios-xe", {
        "TELNET.ENABLED": (False, "config"), "HTTP.ENABLED": (False, "config"), "HTTPS.ENABLED": (False, "config"),
        "SSH.VERSION": 2, "SSH.RETRIES_LIMITED": True, "SSH.TIMEOUT_SET": True,
        "SSH.WEAK_CIPHERS": False, "SSH.MACS_STRONG": True,
        "SNMP.VERSION": 3, "SNMP.V3_PRIV": True, "SNMP.COMMUNITY_PUBLIC": False, "SNMP.READWRITE": False,
        "PASSWORD.ENCRYPTED": True, "PASSWORD.POLICY_STRONG": True, "PASSWORD.MIN_LENGTH": 14,
        "SERVICE.PASSWORD_ENCRYPTION": True, "SERVICE.PAD_DISABLED": (True, "config"),
        "KEY.STORED_SECURE": True, "USER.DEFAULT_ACCOUNTS": False, "CRYPTO.WEAK_ALGO": False,
        "ACL.PERMIT_ANY": False,
        "AAA.AUTHENTICATION": True, "AAA.AUTHORIZATION": True, "AAA.ACCOUNTING": (True, "config"),
        "AAA.TACACS_CONFIGURED": True, "AAA.SERVER_REDUNDANT": True, "AAA.LOCKOUT_ENABLED": (True, "config"),
        "LOGGING.REMOTE_SERVER": True, "LOGGING.BUFFERED": True, "LOGGING.TRAP_LEVEL": "informational",
        "NTP.AUTHENTICATED": True, "NTP.SOURCE_SET": True,
        "VTY.ACL_APPLIED": True, "VTY.TIMEOUT_SET": True, "CONSOLE.SECURED": True, "AUX.DISABLED": True,
        "ROUTING.OSPF_AUTH": True, "ROUTING.BGP_AUTH": True, "ROUTING.AUTH_ENABLED": True,
        "BANNER.MOTD_SET": True, "BANNER.LOGIN_SET": True, "BANNER.EXEC_SET": True,
        "IP.SOURCE_ROUTE_DISABLED": (True, "config"), "URPF.ENABLED": True,
        "IP.REDIRECTS_DISABLED": True, "PROXY_ARP.DISABLED": True,   # loopback excluded, both L3 ifaces compliant
        "CDP.DISABLED_EDGE": (True, "config"), "AUDIT.CONFIG_ARCHIVED": (True, "config"),
        "MONITORING.NETFLOW": True, "DOS.PROTECTION": True, "MGMT.ENCRYPTED_ONLY": True,
    }),
    "arista_eos_leaf.cfg": ("arista", "eos", {
        "TELNET.ENABLED": (False, "config"),            # management telnet / shutdown
        "HTTP.ENABLED": False, "HTTPS.ENABLED": True,   # eAPI protocol https
        "SSH.VERSION": (2, "default"), "SSH.WEAK_CIPHERS": False, "SSH.MACS_STRONG": True, "SSH.TIMEOUT_SET": True,
        "ACL.MGMT_RESTRICTED": True, "MGMT.SESSION_TIMEOUT": True,
        "PASSWORD.ENCRYPTED": True, "USER.DEFAULT_ACCOUNTS": False,   # `admin` with a sha512 secret is operator-set
        "AAA.AUTHENTICATION": True, "AAA.ACCOUNTING": True, "AAA.LOCKOUT_ENABLED": (True, "config"),
        "AAA.SERVER_REDUNDANT": True, "AAA.TACACS_CONFIGURED": True,
        "SNMP.VERSION": 2, "SNMP.COMMUNITY_PUBLIC": False, "SNMP.ACL_RESTRICTED": True,
        "LOGGING.REMOTE_SERVER": True, "LOGGING.TIMESTAMPS": True,
        "NTP.ENABLED": True, "NTP.AUTHENTICATED": False,
        "STP.BPDU_GUARD": True, "ROUTING.OSPF_AUTH": True,
        "MONITORING.NETFLOW": True, "BANNER.LOGIN_SET": True, "BANNER.MOTD_SET": (False, "default"),
        "MGMT.ENCRYPTED_ONLY": True, "ACL.PERMIT_ANY": False,
    }),
    "cisco_nxos_dc_switch.cfg": ("cisco", "nx-os", {
        "TELNET.ENABLED": (True, "config"),             # feature telnet
        "HTTP.ENABLED": True, "HTTPS.ENABLED": True,    # feature nxapi + nxapi http port 80
        "SSH.ENABLED": True, "SSH.VERSION": (2, "default"), "CRYPTO.RSA_KEY_SIZE": 2048,
        "SNMP.COMMUNITY_PUBLIC": True, "SNMP.READWRITE": True, "SNMP.V3_PRIV": True,
        "CRYPTO.WEAK_ALGO": True,                       # snmp-server user ... auth md5
        "PASSWORD.ENCRYPTED": False, "KEY.STORED_SECURE": False,      # username monitor password 0 ...
        "PASSWORD.POLICY_STRONG": (False, "config"),    # no password strength-check
        "USER.DEFAULT_ACCOUNTS": False,
        "ACL.PERMIT_ANY": True, "ACL.MGMT_RESTRICTED": True,
        "LOGGING.REMOTE_SERVER": True, "LOGGING.TIMESTAMPS": True,
        "CONSOLE.SECURED": False, "MGMT.SESSION_TIMEOUT": True,
        "ROUTING.BGP_AUTH": False, "MGMT.ENCRYPTED_ONLY": False,
    }),
    "junos_ex_access_mixed.cfg": ("juniper", "junos", {
        "SSH.VERSION": (2, "config"), "SSH.WEAK_CIPHERS": False, "SSH.MACS_STRONG": True,
        "SSH.RETRIES_LIMITED": True, "SSH.TIMEOUT_SET": True,
        "TELNET.ENABLED": (True, "config"), "HTTP.ENABLED": (False, "default"), "HTTPS.ENABLED": True,
        "CRYPTO.WEAK_ALGO": True,                       # root password hash is MD5-crypt ($1$)
        "USER.DEFAULT_ACCOUNTS": True,                  # `admin` with a $1$ hash
        "PASSWORD.MIN_LENGTH": 12, "PASSWORD.POLICY_STRONG": True,
        "AAA.AUTHENTICATION": True, "AAA.TACACS_CONFIGURED": True, "AAA.SERVER_REDUNDANT": True,
        "AAA.ACCOUNTING": True, "AAA.LOCKOUT_ENABLED": (True, "config"),
        "SNMP.COMMUNITY_PUBLIC": True, "SNMP.READWRITE": False, "SNMP.ACL_RESTRICTED": False,
        "SNMP.V3_PRIV": True, "SNMP.VERSION": 2,
        "LOGGING.REMOTE_SERVER": True, "NTP.ENABLED": True, "NTP.AUTHENTICATED": True, "NTP.SOURCE_SET": True,
        "ACL.MGMT_RESTRICTED": (True, "config"), "MGMT.SESSION_TIMEOUT": True,
        "BANNER.LOGIN_SET": True, "AUDIT.CONFIG_ARCHIVED": True,
        "STP.BPDU_GUARD": True, "DHCP.SNOOPING": True, "PORT_SECURITY.ENABLED": True,
        "CDP.DISABLED_EDGE": (False, "config"),         # protocols lldp
        "KEY.STORED_SECURE": True, "ACL.PERMIT_ANY": False, "MGMT.ENCRYPTED_ONLY": False,
    }),
    "junos_srx_edge_set.cfg": ("juniper", "junos", {
        "TELNET.ENABLED": (False, "default"),           # `deactivate system services telnet` => inactive
        "HTTP.ENABLED": (True, "config"), "HTTPS.ENABLED": True,
        "SSH.WEAK_CIPHERS": True, "CRYPTO.WEAK_ALGO": True,
        "AAA.AUTHENTICATION": True, "AAA.SERVER_REDUNDANT": False,
        "SNMP.COMMUNITY_PUBLIC": False, "SNMP.READWRITE": True, "SNMP.ACL_RESTRICTED": True,
        "ACL.PERMIT_ANY": (True, "config"),             # SRX policy any/any/any permit
        "CRYPTO.IKE_VERSION": 1, "CRYPTO.IPSEC_ENABLED": True, "DOS.PROTECTION": True,
        "URPF.ENABLED": True, "ROUTING.OSPF_AUTH": True, "MONITORING.NETFLOW": True,
        "BANNER.MOTD_SET": True, "BANNER.LOGIN_SET": (False, "default"),
        "USER.DEFAULT_ACCOUNTS": False, "AAA.LOCKOUT_ENABLED": True,
    }),
    "fortios_fg100f_edge.cfg": ("fortinet", "fortios", {
        "TELNET.ENABLED": (False, "config"), "HTTP.ENABLED": (True, "config"),   # wan1 allowaccess includes http
        "HTTPS.ENABLED": True, "SSH.ENABLED": True,
        "MGMT.INTERNET_EXPOSED": (True, "config"),
        "SSH.WEAK_CIPHERS": True,                       # ssh-cbc-cipher enable
        "CRYPTO.TLS_MIN": "TLSv1-1", "CRYPTO.WEAK_ALGO": True,
        "AAA.LOCKOUT_ENABLED": (True, "config"), "MGMT.SESSION_TIMEOUT": (True, "config"),
        "ACL.MGMT_RESTRICTED": False,                   # admin `admin` has no trusthost
        "USER.DEFAULT_ACCOUNTS": True, "PASSWORD.ENCRYPTED": True,
        "PASSWORD.POLICY_STRONG": True, "PASSWORD.MIN_LENGTH": 12,
        "AAA.TACACS_CONFIGURED": True, "AAA.AUTHENTICATION": (False, "default"),
        "SNMP.COMMUNITY_PUBLIC": True, "SNMP.ACL_RESTRICTED": False, "SNMP.V3_PRIV": True, "SNMP.READWRITE": False,
        "LOGGING.REMOTE_SERVER": True, "NTP.ENABLED": True, "NTP.AUTHENTICATED": False,
        "BANNER.LOGIN_SET": True, "BANNER.MOTD_SET": (False, "default"),
        "ACL.PERMIT_ANY": (True, "config"), "DOS.PROTECTION": (False, "default"),
        "CRYPTO.IKE_VERSION": 1, "CRYPTO.PFS_ENABLED": False,
        "AUDIT.CONFIG_ARCHIVED": True, "CDP.DISABLED_EDGE": (False, "config"),
        "MGMT.ENCRYPTED_ONLY": False,
    }),
    "panos_pa850_set.cfg": ("paloalto", "pan-os", {
        "TELNET.ENABLED": (False, "config"), "HTTP.ENABLED": (True, "config"),  # disable-http no
        "MGMT.INTERNET_EXPOSED": (True, "config"),      # MGMT-ADMIN (ssh/https/http) on the untrust interface
        "SSH.WEAK_CIPHERS": True, "CRYPTO.WEAK_ALGO": True,
        "ACL.MGMT_RESTRICTED": True, "MGMT.SESSION_TIMEOUT": (True, "config"),
        "AAA.LOCKOUT_ENABLED": True, "AAA.AUTHENTICATION": True, "AAA.TACACS_CONFIGURED": True,
        "USER.DEFAULT_ACCOUNTS": True, "PASSWORD.MIN_LENGTH": 12, "PASSWORD.POLICY_STRONG": True,
        "SNMP.COMMUNITY_PUBLIC": True, "SNMP.READWRITE": False, "SNMP.V3_PRIV": False,
        "LOGGING.REMOTE_SERVER": True, "NTP.ENABLED": True, "NTP.AUTHENTICATED": False,
        "BANNER.LOGIN_SET": True,
        "ACL.PERMIT_ANY": (True, "config"),             # rule temp-allow-all
        "DOS.PROTECTION": True, "ZONE.SECURED": True,
        "CRYPTO.IKE_VERSION": 1, "CRYPTO.IPSEC_ENABLED": True, "CRYPTO.PFS_ENABLED": False,
        "CRYPTO.TLS_MIN": "tls1-1", "MGMT.ENCRYPTED_ONLY": False,
    }),
}

# Properties each platform must declare "not applicable" rather than leave as unknown/failed.
EXPECTED_NA = {
    "cisco_iosxe_core_hardened.cfg": {"STP.BPDU_GUARD", "DHCP.SNOOPING", "PORT_SECURITY.ENABLED"},   # router
    "arista_eos_leaf.cfg": {"SERVICE.PASSWORD_ENCRYPTION", "SERVICE.PAD_DISABLED"},
    "fortios_fg100f_edge.cfg": {"SERVICE.PASSWORD_ENCRYPTION", "STP.BPDU_GUARD", "IP.REDIRECTS_DISABLED",
                                "ROUTING.OSPF_AUTH"},
    "panos_pa850_set.cfg": {"SERVICE.PAD_DISABLED", "PORT_SECURITY.ENABLED", "ROUTING.BGP_AUTH"},
    "junos_srx_edge_set.cfg": {"SERVICE.FINGER_DISABLED", "DHCP.SNOOPING"},
}


def _load(name):
    vendor, platform, _ = EXPECTED[name]
    text = (CORPUS / name).read_text(encoding="utf-8")
    return text, vendor_parsers.parse(text, vendor, platform)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_ground_truth(name):
    text, res = _load(name)
    assert res is not None
    wrong = []
    for prop, want in EXPECTED[name][2].items():
        value, basis = want if isinstance(want, tuple) else (want, None)
        if prop not in res.flat:
            wrong.append(f"{prop}: missing (wanted {value!r})")
            continue
        got_basis = res.provenance[prop]["basis"]
        if res.flat[prop] != value or (basis and got_basis != basis):
            wrong.append(f"{prop}: got {res.flat[prop]!r}/{got_basis}, wanted {value!r}/{basis or '*'}")
    assert not wrong, f"{name}:\n  " + "\n  ".join(wrong)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_evidence_points_at_real_lines(name):
    """Every 'config' fact carries a line number whose text really is in the file; defaults carry a note."""
    text, res = _load(name)
    lines = text.splitlines()
    for prop, p in res.provenance.items():
        if p["basis"] == "config" and p["line_no"]:
            assert 1 <= p["line_no"] <= len(lines), prop
            assert p["line"] == lines[p["line_no"] - 1].strip(), prop
        if p["basis"] == "default":
            assert p.get("note"), f"{prop}: assumed default without an explanation"
            assert p["confidence"] < 1.0


@pytest.mark.parametrize("name", sorted(EXPECTED_NA))
def test_not_applicable_declared(name):
    _, res = _load(name)
    missing = EXPECTED_NA[name] - set(res.not_applicable)
    assert not missing, f"{name}: should be N/A: {sorted(missing)}"
    assert not (set(res.not_applicable) & set(res.flat)), "a property cannot be both known and N/A"


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_nearly_every_line_is_understood(name):
    """Unknown-token queue must stay small: structured parsers consume benign + recognised lines."""
    text, res = _load(name)
    meaningful = [i for i, l in enumerate(text.splitlines(), 1)
                  if l.strip() and not l.strip().startswith(("!", "#"))]
    unexplained = [i for i in meaningful if i not in res.consumed]
    assert len(unexplained) <= max(2, len(meaningful) // 50), \
        f"{name}: {len(unexplained)} unexplained lines e.g. {[text.splitlines()[i-1] for i in unexplained[:4]]}"


def test_fingerprints():
    cases = {
        "arista_eos_leaf.cfg": ("arista", "eos", "4.31.2F"),
        "cisco_iosxe_core_hardened.cfg": ("cisco", "ios-xe", "17.9"),
        "cisco_nxos_dc_switch.cfg": ("cisco", "nx-os", "10.3(4a)"),
        "fortios_fg100f_edge.cfg": ("fortinet", "fortios", "7.2.5"),
        "junos_ex_access_mixed.cfg": ("juniper", "junos", "20.4R3-S2.3"),
        "junos_srx_edge_set.cfg": ("juniper", "junos", "21.2R3-S4.3"),
        "panos_pa850_set.cfg": ("paloalto", "pan-os", None),
    }
    for name, (vendor, platform, version) in cases.items():
        fp = fingerprint((CORPUS / name).read_text(encoding="utf-8"))
        assert fp and (fp["vendor"], fp["platform"], fp["version"]) == (vendor, platform, version), name
    assert fingerprint("hello world\nnothing distinctive here\n") is None
    assert fingerprint("") is None


# ----------------------------------------------------------------------------- formats
def test_junos_brace_and_set_formats_agree():
    brace = ("system {\n  services {\n    ssh {\n      protocol-version v2;\n    }\n    telnet;\n  }\n"
             "  login {\n    retry-options {\n      tries-before-disconnect 3;\n    }\n  }\n}\n")
    setfmt = ("set system services ssh protocol-version v2\nset system services telnet\n"
              "set system login retry-options tries-before-disconnect 3\n")
    a, b = vendor_parsers.parse(brace, "juniper"), vendor_parsers.parse(setfmt, "juniper")
    for prop in ("SSH.VERSION", "TELNET.ENABLED", "SSH.RETRIES_LIMITED", "SSH.ENABLED"):
        assert a.flat[prop] == b.flat[prop], prop
    assert a.flat["TELNET.ENABLED"] is True


def test_junos_inactive_and_deactivate_are_ignored():
    brace = "system {\n  services {\n    inactive: telnet;\n    ssh;\n  }\n}\n"
    assert vendor_parsers.parse(brace, "juniper").flat["TELNET.ENABLED"] is False
    setfmt = "set system services telnet\ndeactivate system services telnet\n"
    assert vendor_parsers.parse(setfmt, "juniper").flat["TELNET.ENABLED"] is False


def test_junos_trailing_secret_comments_do_not_hide_lines():
    cfg_text = ('system {\n  root-authentication {\n    encrypted-password "$1$abc$def"; ## SECRET-DATA\n  }\n}\n')
    assert vendor_parsers.parse(cfg_text, "juniper").flat["CRYPTO.WEAK_ALGO"] is True


PAN_XML = """<config version="10.2.0" urldb="paloaltonetworks">
  <mgt-config><users><entry name="admin"><phash>$1$x$y</phash></entry></users></mgt-config>
  <devices><entry name="localhost.localdomain">
    <deviceconfig><system>
      <service><disable-telnet>no</disable-telnet><disable-http>yes</disable-http></service>
      <permitted-ip><entry name="10.0.0.0/24"/></permitted-ip>
    </system></deviceconfig>
    <vsys><entry name="vsys1"><rulebase><security><rules>
      <entry name="any-any"><from><member>any</member></from><to><member>any</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <application><member>any</member></application><service><member>any</member></service>
        <action>allow</action></entry>
    </rules></security></rulebase></entry></vsys>
  </entry></devices>
</config>"""


def test_panos_xml_format():
    res = vendor_parsers.parse(PAN_XML, "paloalto")
    assert res.flat["TELNET.ENABLED"] is True and res.provenance["TELNET.ENABLED"]["basis"] == "config"
    assert res.flat["HTTP.ENABLED"] is False
    assert res.flat["ACL.MGMT_RESTRICTED"] is True
    assert res.flat["ACL.PERMIT_ANY"] is True
    assert res.flat["USER.DEFAULT_ACCOUNTS"] is True
    assert res.provenance["TELNET.ENABLED"]["line_no"] == PAN_XML.splitlines().index(
        next(l for l in PAN_XML.splitlines() if "disable-telnet" in l)) + 1      # real XML line numbers


def test_panos_xml_hostile_input_is_contained():
    bomb = '<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><config>&b;</config>'
    t0 = time.perf_counter()
    res = vendor_parsers.parse(bomb, "paloalto")
    assert res is not None and time.perf_counter() - t0 < 2
    res = vendor_parsers.parse("<config><unclosed>", "paloalto")      # malformed XML must not raise
    assert res is not None


# ------------------------------------------------------------------ robustness / abuse
GARBAGE = ["", "\n\n\n", "!", "}" * 50, "{" * 50, "config", "end\nend\nend", "set", "set set set",
           "banner motd ^C\nnever closed", "line vty 0 4\n" * 500, "\x00\x01\x02binary\xff", "a" * 100000,
           "interface\n interface\n  interface", "crypto pki certificate chain X\n 3082\n"]


@pytest.mark.parametrize("vendor", ["cisco", "arista", "juniper", "fortinet", "paloalto"])
def test_parsers_never_raise_on_garbage(vendor):
    for text in GARBAGE:
        res = vendor_parsers.parse(text, vendor, "")
        assert res is not None and isinstance(res.flat, dict)
    rnd = random.Random(1234)
    alphabet = string.ascii_letters + string.digits + " \t\n{};[]\"'#!-./:"
    for _ in range(60):
        blob = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(1, 3000)))
        assert vendor_parsers.parse(blob, vendor, "") is not None


@pytest.mark.parametrize("vendor,name", [("cisco", "cisco_iosxe_branch_insecure.cfg"),
                                         ("juniper", "junos_ex_access_mixed.cfg"),
                                         ("fortinet", "fortios_fg100f_edge.cfg"),
                                         ("paloalto", "panos_pa850_set.cfg")])
def test_parse_time_scales_linearly(vendor, name):
    text = (CORPUS / name).read_text(encoding="utf-8")
    big = "\n".join([text] * 40)          # a few thousand lines
    t0 = time.perf_counter()
    vendor_parsers.parse(big, vendor, "")
    assert time.perf_counter() - t0 < 5, "parser is too slow on a multi-thousand-line config"


def test_truncated_config_gives_unknown_not_a_pass():
    """A cut-off config must not manufacture passing verdicts for what it never showed."""
    text = (CORPUS / "cisco_iosxe_core_hardened.cfg").read_text(encoding="utf-8")
    head = "\n".join(text.splitlines()[:30])          # stops before logging, NTP, vty, SNMP, routing...
    res = vendor_parsers.parse(head, "cisco", "ios-xe")
    assert "TELNET.ENABLED" not in res.flat              # no `line vty` block seen -> not determined
    assert "ROUTING.OSPF_AUTH" not in res.flat
    assert "VTY.ACL_APPLIED" not in res.flat
    assert res.provenance["SNMP.ENABLED"]["basis"] == "default"
