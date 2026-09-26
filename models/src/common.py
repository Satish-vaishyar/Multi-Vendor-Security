"""Shared constants/helpers for models M1-M13. Offline-safe, deterministic."""
from __future__ import annotations
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
DATASETS = ROOT / "datasets"
ARTIFACTS = ROOT / "artifacts"
EVAL = ROOT / "evaluation"

VENDORS = ["cisco", "juniper", "fortinet", "paloalto", "arista", "unknown"]
KNOWN_VENDORS = VENDORS[:5]

# ~120 canonical properties frozen before M3 training (models.md §9-10)
CANONICAL_PROPERTIES: list[str] = [
    # device (5)
    "device.vendor", "device.platform", "device.version", "device.hostname", "device.serial",
    # aaa (8)
    "aaa.authentication", "aaa.authorization", "aaa.accounting", "aaa.mfa",
    "aaa.password_policy", "aaa.lockout", "aaa.tacacs", "aaa.radius",
    # services ssh/telnet/http (14)
    "services.ssh", "services.ssh.version", "services.ssh.timeout", "services.ssh.retries",
    "services.ssh.ciphers", "services.telnet", "services.http", "services.https",
    "services.https.redirect", "services.snmp", "services.snmp.version", "services.snmp.community",
    "services.ntp", "services.ntp.auth",
    # logging (6)
    "logging.enabled", "logging.remote_syslog", "logging.timestamp", "logging.level",
    "logging.host", "logging.buffered",
    # acl (6)
    "acl.enabled", "acl.rules", "acl.management", "acl.default_policy", "acl.established", "acl.log",
    # crypto (12)
    "crypto.algorithm", "crypto.key_size", "crypto.tls_version", "crypto.ssh_algorithm",
    "crypto.certificate", "crypto.dh_group", "crypto.ike", "crypto.ipsec",
    "crypto.password_encryption", "crypto.enable_secret", "crypto.ssh_ciphers", "crypto.ssh_macs",
    # interfaces (8)
    "interfaces.admin", "interfaces.description", "interfaces.ip", "interfaces.shutdown",
    "interfaces.proxy_arp", "interfaces.source_route", "interfaces.dhcp_snoop", "interfaces.mtu",
    # routing (6)
    "routing.ospf", "routing.bgp", "routing.static", "routing.redistribute", "routing.auth", "routing.filter",
    # policies (8)
    "policies.motd", "policies.exec_timeout", "policies.session_timeout", "policies.block",
    "policies.port_security", "policies.storm_control", "policies.dai", "policies.urp",
    # mgmt plane (8)
    "mgmt.plane_acl", "mgmt.vty_ssh_only", "mgmt.http_disabled", "mgmt.snmp_priv",
    "mgmt.ntp_auth", "mgmt.aaa", "mgmt.logging", "mgmt.banner",
    # software (6)
    "software.os", "software.version", "software.image", "software.patch", "software.eol", "software.signed",
    # pqc/crypto-agility extras (10)
    "pqc.rsa", "pqc.ecdsa", "pqc.dh", "pqc.aes", "pqc.sha", "pqc.tls", "pqc.ssh_kex",
    "pqc.snmp_priv", "pqc.cert_algo", "pqc.hybrid",
    # misc to reach ~120 (23)
    "net.dns", "net.domain", "net.hostname_lookup", "net.cdp", "net.lldp",
    "net.aux", "net.console_timeout", "net.vty_acl", "net.ssh_timeout", "net.http_auth",
    "net.snmp_trap", "net.syslog_facility", "net.ntp_source", "net.aaa_fallback",
    "net.radius_key", "net.tacacs_key", "net.cert_expiry", "net.key_length",
    "net.tls_min", "net.ssh_mac", "net.banner_login", "net.fqdn", "net.timesource",
]
assert 100 <= len(CANONICAL_PROPERTIES) <= 150, len(CANONICAL_PROPERTIES)

# Vendor signature keywords for M1 rules
VENDOR_SIGNATURES: dict[str, list[str]] = {
    "cisco": ["gigabitethernet", "router ospf", "ip access-list", "snmp-server", "service password-encryption",
              "line vty", "ip ssh version", "no ip http server", "aaa new-model", "tacacs-server"],
    "juniper": ["set system services", "set interfaces", "delete system", "junos", "set security ike",
                "set system syslog", "set system ntp", "commit"],
    "fortinet": ["config system", "set admin-", "fortigate", "fortios", "set allowaccess", "edit \"port"],
    "paloalto": ["set deviceconfig", "set network", "pan-os", "vsys", "security-policy", "set rulebase"],
    "arista": ["eos", "arista", "management api", "daemon terminattr", "ip routing", "switchport"],
    "unknown": ["blorp", "hyperflux", "secure-mgmt", "mgmt telnet", "web-mgmt", "telemetry community",
                "event-sink", "time-sync", "vault lock"],
}

# Per-vendor command templates: canonical_path -> list of vendor commands (value implied)
# Used by dataset builder to guarantee 20+ commands/property for core props.
COMMAND_MAP: dict[str, dict[str, list[str]]] = {
    "cisco": {
        "services.ssh.version": ["ip ssh version 2", "ip ssh version 1"],
        "services.telnet": ["line vty 0 4\n transport input ssh", "line vty 0 4\n transport input telnet"],
        "services.http": ["no ip http server", "ip http server"],
        "services.https": ["ip http secure-server", "no ip http secure-server"],
        "services.snmp": ["snmp-server group NETADMIN v3 priv", "snmp-server community public RO"],
        "logging.enabled": ["logging host 10.0.0.99", "no logging"],
        "aaa.authentication": ["aaa new-model", "no aaa new-model"],
        "crypto.key_size": ["crypto key generate rsa modulus 2048", "crypto key generate rsa modulus 1024"],
    },
    "juniper": {
        "services.ssh.version": ["set system services ssh protocol-version v2", "set system services ssh protocol-version v1"],
        "services.telnet": ["delete system services telnet", "set system services telnet"],
        "services.http": ["delete system services web-management http", "set system services web-management http"],
        "logging.enabled": ["set system syslog host 10.0.0.99 any any", "delete system syslog"],
        "aaa.authentication": ["set system authentication-order tacplus", "delete system tacplus-server"],
        "crypto.key_size": ["set security ike proposal strong dh-group14", "set security ike proposal weak dh-group1"],
    },
    "fortinet": {
        "services.ssh.version": ["set admin-https-redirect enable", "set admin-telnet enable"],
        "services.telnet": ["set admin-telnet disable", "set admin-telnet enable"],
        "services.http": ["set admin-http disable", "set admin-http enable"],
        "logging.enabled": ["set syslog-server 10.0.0.99", "unset syslog-server"],
        "aaa.authentication": ["set auth-type tacacs+", "set auth-type local"],
    },
    "paloalto": {
        "services.ssh.version": ["set deviceconfig system ssh protocol v2", "set deviceconfig system ssh protocol v1"],
        "services.telnet": ["set deviceconfig system telnet disable", "set deviceconfig system telnet enable"],
        "services.http": ["set deviceconfig system http disable", "set deviceconfig system http enable"],
        "logging.enabled": ["set deviceconfig system syslog-server 10.0.0.99", "delete deviceconfig system syslog"],
    },
    "arista": {
        "services.ssh.version": ["ssh protocol version 2", "ssh protocol version 1"],
        "services.telnet": ["no telnet server", "telnet server enable"],
        "services.http": ["no http server", "http server enable"],
        "logging.enabled": ["logging host 10.0.0.99", "no logging"],
    },
    "unknown": {
        "services.ssh.version": ["secure-mgmt ssh protocol v2", "secure-mgmt ssh protocol v1"],
        "services.telnet": ["mgmt telnet deny", "mgmt telnet permit-all"],
        "services.http": ["web-mgmt plain disable", "web-mgmt plain enable"],
        "logging.enabled": ["event-sink remote 10.0.0.99", "event-sink none"],
    },
}


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def normalize_text(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())


def device_split(items: list, seed: int = 42, ratios=(0.7, 0.15, 0.15)):
    """Deterministic device/config-level split (no line leakage)."""
    import random
    rng = random.Random(seed)
    idx = list(range(len(items)))
    rng.shuffle(idx)
    n = len(items)
    n_tr = int(n * ratios[0])
    n_va = int(n * ratios[1])
    tr = [items[i] for i in idx[:n_tr]]
    va = [items[i] for i in idx[n_tr:n_tr + n_va]]
    te = [items[i] for i in idx[n_tr + n_va:]]
    return tr, va, te
