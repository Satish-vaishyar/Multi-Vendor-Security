"""Compliance / CVE(vulnerabilities) / PQC / Analytics(security) read APIs (api.md §13-18)."""
from __future__ import annotations
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional

from app.core import config as cfg
from app.core import persist as db
from app.core import store
from app.services.integration import okf_layer, cve_layer
from app.engines import security as sec_eng

compliance_router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])
vuln_router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["vulnerabilities"])
pqc_router = APIRouter(prefix="/api/v1/pqc", tags=["pqc"])
analytics_router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])


def _audit_cols(audit_id: str, columns: list) -> dict:
    """One projected audit read (never the full findings/canonical_ir payload)."""
    rows = db.select("audits", ["audit_id"] + columns, limit=1, audit_id=audit_id)
    if not rows:
        raise HTTPException(404, "Audit not found")
    return rows[0]


def _audit(audit_id: str) -> dict:
    rec = db.get("audits", audit_id)
    if not rec:
        raise HTTPException(404, "Audit not found")
    return rec


@compliance_router.get("/frameworks")
def frameworks():
    okf = okf_layer()
    return cfg.ok([{"id": f.framework_id, "name": f.name, "version": f.version}
                   for f in okf["fwk"].frameworks.values()])


@compliance_router.get("/{audit_id}")
def compliance_overall(audit_id: str):
    rec = _audit_cols(audit_id, ["compliance", "by_framework"])
    return cfg.ok({"audit_id": audit_id, "score": rec["compliance"],
                   "by_framework": rec.get("by_framework", {})})


@compliance_router.get("/{audit_id}/framework/{framework}")
def compliance_framework(audit_id: str, framework: str):
    rec = _audit_cols(audit_id, ["by_framework"])
    by_fw = rec.get("by_framework", {}) or {}
    fw = by_fw.get(framework.upper(), by_fw.get(framework, {}))
    if not fw:
        raise HTTPException(404, f"No data for framework {framework}")
    return cfg.ok({"framework": framework.upper(), "score": fw.get("compliance_score"), "controls": fw})


# Per-property guidance so the compliance UI never renders blanks or
# severity-bucket boilerplate. Each entry is grounded in the control's
# actual condition (property + expected value), not hardcoded per finding.
_PROPERTY_GUIDE: dict = {
    "SSH.VERSION": {"about": "SSH protocol version negotiated for remote admin sessions.",
        "fix_title": "Enforce SSH version 2", "commands": ["ip ssh version 2"],
        "validation": ["show ip ssh"],
        "impact": "SSHv1 allows ciphertext downgrade and MITM credential recovery against admin sessions."},
    "SSH.ENABLED": {"about": "Whether the SSH service is running for remote administration.",
        "fix_title": "Enable SSH for secure remote access", "commands": ["ip domain-name example.local", "crypto key generate rsa modulus 2048", "ip ssh version 2", "line vty 0 4", "transport input ssh"],
        "validation": ["show ip ssh"],
        "impact": "Without SSH there is no encrypted remote administration channel."},
    "SSH.WEAK_CIPHERS": {"about": "Whether weak SSH ciphers/MACs are offered.",
        "fix_title": "Remove weak SSH ciphers", "commands": ["ip ssh server algorithm encryption aes128-ctr aes256-ctr", "ip ssh server algorithm mac hmac-sha2-256"],
        "validation": ["show ip ssh"],
        "impact": "Weak ciphers let a passive observer decrypt captured admin sessions."},
    "SSH.TIMEOUT_SET": {"about": "Idle timeout on SSH sessions.",
        "fix_title": "Set SSH timeout", "commands": ["ip ssh time-out 60", "ip ssh authentication-retries 3"],
        "validation": ["show running-config | include ip ssh"],
        "impact": "Idle SSH sessions stay hijackable indefinitely."},
    "SSH.RETRIES_LIMITED": {"about": "Limit on SSH authentication retries.",
        "fix_title": "Limit SSH authentication retries", "commands": ["ip ssh authentication-retries 3"],
        "validation": ["show running-config | include ip ssh"],
        "impact": "Unlimited retries allow password-guessing against admin logins."},
    "TELNET.ENABLED": {"about": "Whether Telnet (cleartext remote shell) is running.",
        "fix_title": "Disable Telnet, enforce SSH-only VTY access", "commands": ["line vty 0 4", "transport input ssh"],
        "validation": ["show running-config | include transport input"],
        "impact": "Telnet sends admin usernames and passwords in cleartext — any sniffer on the path owns the device."},
    "HTTP.ENABLED": {"about": "Whether cleartext HTTP management is running.",
        "fix_title": "Disable cleartext HTTP management", "commands": ["no ip http server", "ip http secure-server"],
        "validation": ["show running-config | include ip http"],
        "impact": "HTTP management exposes admin credentials and session cookies to network sniffing."},
    "FTP.ENABLED": {"about": "Whether cleartext FTP service is running.",
        "fix_title": "Disable FTP, use SCP/SFTP", "commands": ["no ip ftp server", "ip scp server enable"],
        "validation": ["show running-config | include ftp"],
        "impact": "FTP leaks file-transfer credentials and config contents in cleartext."},
    "TFTP.ENABLED": {"about": "Whether TFTP (unauthenticated file transfer) is running.",
        "fix_title": "Disable TFTP", "commands": ["no tftp-server"],
        "validation": ["show running-config | include tftp"],
        "impact": "TFTP has no authentication — anyone on the network can push or pull files including configs."},
    "SNMP.COMMUNITY_PUBLIC": {"about": "Whether the well-known 'public'/'private' SNMP community strings exist.",
        "fix_title": "Remove default SNMP community strings", "commands": ["no snmp-server community public", "no snmp-server community private"],
        "validation": ["show running-config | include snmp-server community"],
        "impact": "Default communities are the first thing scanners try — they expose inventory and often allow config writes."},
    "SNMP.ENABLED": {"about": "Whether SNMP is running at all.",
        "fix_title": "Disable SNMP or move to SNMPv3", "commands": ["no snmp-server", "snmp-server group ADMIN v3 priv"],
        "validation": ["show running-config | include snmp-server"],
        "impact": "Unneeded SNMP widens the remotely reachable attack surface."},
    "SNMP.VERSION": {"about": "SNMP protocol version in use.",
        "fix_title": "Move SNMP to v3", "commands": ["snmp-server group ADMIN v3 priv", "snmp-server user admin ADMIN v3 auth sha <hash> priv aes 128 <key>"],
        "validation": ["show snmp group"],
        "impact": "SNMP v1/v2c have no encryption — community strings and polled data travel in cleartext."},
    "SNMP.V3_PRIV": {"about": "Whether SNMPv3 privacy (authPriv encryption) is configured.",
        "fix_title": "Enable SNMPv3 authPriv", "commands": ["snmp-server user admin ADMIN v3 auth sha <hash> priv aes 128 <key>"],
        "validation": ["show snmp user"],
        "impact": "SNMPv3 without privacy still leaks polled management data to sniffers."},
    "SNMP.READWRITE": {"about": "Whether SNMP has write access to device state.",
        "fix_title": "Restrict SNMP to read-only", "commands": ["no snmp-server community <name> RW", "snmp-server community <name> RO <acl>"],
        "validation": ["show running-config | include snmp-server community"],
        "impact": "SNMP write access lets an attacker with the community string change device configuration."},
    "AAA.AUTHENTICATION": {"about": "Whether centralized AAA authentication gates admin logins.",
        "fix_title": "Configure AAA authentication", "commands": ["aaa new-model", "aaa authentication login default group tacacs+ local"],
        "validation": ["show running-config | include aaa authentication"],
        "impact": "Without AAA, admin access falls back to shared local passwords with no per-user accountability."},
    "AAA.LOCKOUT_ENABLED": {"about": "Whether repeated failed logins trigger lockout/throttling.",
        "fix_title": "Enable login lockout", "commands": ["login block-for 120 attempts 3 within 60"],
        "validation": ["show running-config | include login block"],
        "impact": "No lockout means unlimited password guessing against admin logins."},
    "PASSWORD.ENCRYPTED": {"about": "Whether stored passwords use strong hashing (secret), not cleartext.",
        "fix_title": "Store passwords encrypted", "commands": ["enable secret <strong>", "username admin secret <strong>", "no password <cleartext>"],
        "validation": ["show running-config | include secret"],
        "impact": "Cleartext or reversible passwords in the config give immediate admin access to anyone who reads a backup."},
    "PASSWORD.POLICY_STRONG": {"about": "Whether a strong local password policy (length/complexity) is enforced.",
        "fix_title": "Enforce strong password policy", "commands": ["security passwords min-length 12", "password complexity enable"],
        "validation": ["show running-config | include password"],
        "impact": "Weak policy means short, guessable admin passwords that fall to dictionary attacks."},
    "SERVICE.PASSWORD_ENCRYPTION": {"about": "Whether reversible passwords in the config are obfuscated.",
        "fix_title": "Enable service password-encryption", "commands": ["service password-encryption"],
        "validation": ["show running-config | include service password-encryption"],
        "impact": "Reversible passwords are trivially decoded from any leaked config file."},
    "USER.DEFAULT_ACCOUNTS": {"about": "Whether factory default accounts still exist.",
        "fix_title": "Remove default vendor accounts", "commands": ["no username admin", "no username cisco", "no username guest", "username <unique-admin> privilege 15 secret <strong>"],
        "validation": ["show running-config | include username"],
        "impact": "Default credentials are published and scanned for within minutes of exposure."},
    "ACL.MGMT_RESTRICTED": {"about": "Whether VTY/management access is restricted to trusted sources by ACL.",
        "fix_title": "Restrict management access by ACL", "commands": ["ip access-list standard MGMT-ALLOW", "permit 10.0.0.0 0.0.0.255", "line vty 0 4", "access-class MGMT-ALLOW in"],
        "validation": ["show running-config | include access-class"],
        "impact": "Unrestricted VTY exposes admin login to the whole network, including compromised segments."},
    "ACL.PERMIT_ANY": {"about": "Whether an overly permissive permit-any rule exists.",
        "fix_title": "Remove permit-any, scope permits", "commands": ["ip access-list extended MGMT-IN", "no permit ip any any", "permit tcp 10.0.0.0 0.0.0.255 any eq 22", "deny ip any any log"],
        "validation": ["show access-lists"],
        "impact": "A permit-any rule nullifies segmentation — any host can reach protected services."},
    "LOGGING.ENABLED": {"about": "Whether local audit logging is enabled.",
        "fix_title": "Enable logging", "commands": ["logging on", "logging buffered 16384 informational"],
        "validation": ["show logging"],
        "impact": "Without logs there is no record of who changed what — incidents become un-investigable."},
    "LOGGING.REMOTE_SERVER": {"about": "Whether logs are forwarded to a remote syslog collector.",
        "fix_title": "Forward logs to remote syslog", "commands": ["logging host 10.0.0.50", "logging trap informational"],
        "validation": ["show running-config | include logging host"],
        "impact": "Local-only logs are lost on reboot or wiped by an attacker covering tracks."},
    "LOGGING.TIMESTAMPS": {"about": "Whether log entries carry timestamps.",
        "fix_title": "Enable log timestamps", "commands": ["service timestamps log datetime msec localtime"],
        "validation": ["show running-config | include timestamps"],
        "impact": "Timestamp-less logs cannot be ordered or correlated across devices during response."},
    "NTP.ENABLED": {"about": "Whether the clock is synchronized via NTP.",
        "fix_title": "Enable NTP", "commands": ["ntp server 10.0.0.53", "clock timezone UTC 0"],
        "validation": ["show ntp status"],
        "impact": "Clock drift breaks log correlation, certificate validation and time-based access rules."},
    "NTP.AUTHENTICATED": {"about": "Whether NTP uses authenticated sources.",
        "fix_title": "Authenticate NTP sources", "commands": ["ntp authenticate", "ntp trusted-key 1", "ntp server 10.0.0.53 key 1"],
        "validation": ["show running-config | include ntp"],
        "impact": "Unauthenticated NTP lets an attacker shift device time and poison audit data."},
    "CRYPTO.WEAK_ALGO": {"about": "Whether deprecated algorithms (DES/3DES/MD5/RC4/SHA1/DH-group1) are configured.",
        "fix_title": "Remove weak crypto algorithms", "commands": ["no ip ssh server algorithm encryption 3des-cbc", "crypto ikev2 proposal STRONG", "encryption aes-gcm-256", "integrity sha256", "group 14"],
        "validation": ["show running-config | include crypto"],
        "impact": "Weak algorithms are practically breakable — encrypted sessions can be decrypted offline."},
    "CRYPTO.RSA_KEY_SIZE": {"about": "Size of the device RSA host key.",
        "fix_title": "Use RSA keys of at least 2048 bits", "commands": ["crypto key generate rsa modulus 2048 label SSH-KEYS"],
        "validation": ["show crypto key mypubkey rsa"],
        "impact": "Short RSA keys (1024-bit and below) are within reach of brute force."},
    "CRYPTO.IKE_VERSION": {"about": "IKE version used for IPsec negotiation.",
        "fix_title": "Move VPNs to IKEv2", "commands": ["crypto ikev2 proposal STRONG", "encryption aes-gcm-256", "crypto ikev2 policy DEFAULT", "proposal STRONG"],
        "validation": ["show crypto ikev2 sa"],
        "impact": "IKEv1 has unfixable weaknesses that allow session hijack and downgrade."},
    "CRYPTO.IPSEC_ENABLED": {"about": "Whether IPsec is in use (matters only with IKE version).",
        "fix_title": "Use IKEv2 where IPsec is enabled", "commands": ["crypto ikev2 enable"],
        "validation": ["show crypto session"],
        "impact": "IPsec negotiated under IKEv1 inherits its weaknesses."},
    "KEY.STORED_SECURE": {"about": "Whether private keys and PKI material are stored encrypted with a trusted chain.",
        "fix_title": "Store keys encrypted with trusted CA chain", "commands": ["crypto key generate rsa modulus 2048 label DEVICE", "crypto pki trustpoint CORP-CA", "enrollment url http://ca.example.local/certsrv/mscep/mscep.dll", "crypto pki authenticate CORP-CA", "crypto pki enroll CORP-CA"],
        "validation": ["show crypto pki certificates"],
        "impact": "Poorly stored keys let an attacker clone device identity, intercept management or forge certificates."},
    "IP.SOURCE_ROUTE_DISABLED": {"about": "Whether IP source routing is disabled.",
        "fix_title": "Disable IP source routing", "commands": ["no ip source-route"],
        "validation": ["show running-config | include source-route"],
        "impact": "Source routing lets attackers dictate packet paths and bypass boundary controls."},
    "IP.REDIRECTS_DISABLED": {"about": "Whether ICMP redirects are disabled on interfaces.",
        "fix_title": "Disable ICMP redirects", "commands": ["interface GigabitEthernet0/0", "no ip redirects"],
        "validation": ["show running-config interface"],
        "impact": "ICMP redirects let an attacker reroute device traffic through a sniffer."},
    "PROXY_ARP.DISABLED": {"about": "Whether proxy ARP is disabled.",
        "fix_title": "Disable proxy ARP", "commands": ["interface GigabitEthernet0/0", "no ip proxy-arp"],
        "validation": ["show running-config interface"],
        "impact": "Proxy ARP answers leak reachability and aid lateral movement and spoofing."},
    "ROUTING.AUTH_ENABLED": {"about": "Whether routing protocol updates are authenticated.",
        "fix_title": "Authenticate routing peers", "commands": ["router ospf 1", "area 0 authentication message-digest", "ip ospf message-digest-key 1 md5 <key>"],
        "validation": ["show running-config | include authentication"],
        "impact": "Unauthenticated routing lets an attacker inject routes and blackhole or intercept traffic."},
    "ROUTING.OSPF_AUTH": {"about": "Whether OSPF authentication is configured.",
        "fix_title": "Enable OSPF authentication", "commands": ["router ospf 1", "area 0 authentication message-digest"],
        "validation": ["show ip ospf interface"],
        "impact": "Rogue OSPF neighbors can rewrite the routing table."},
    "ROUTING.BGP_AUTH": {"about": "Whether BGP sessions use MD5/TCP-AO authentication.",
        "fix_title": "Authenticate BGP sessions", "commands": ["router bgp 65000", "neighbor 10.0.0.2 password <strong>"],
        "validation": ["show running-config | include neighbor"],
        "impact": "Unauthenticated BGP lets attackers hijack prefixes and divert traffic."},
    "BANNER.LOGIN_SET": {"about": "Whether a login banner warns against unauthorized access.",
        "fix_title": "Configure login banner", "commands": ["banner login ^", "Authorized use only. All activity is monitored.", "^"],
        "validation": ["show running-config | include banner"],
        "impact": "Missing banners weaken legal standing when prosecuting unauthorized access."},
    "BANNER.MOTD_SET": {"about": "Whether a message-of-the-day banner is configured.",
        "fix_title": "Configure MOTD banner", "commands": ["banner motd ^", "Authorized use only.", "^"],
        "validation": ["show running-config | include banner"],
        "impact": "Missing MOTD removes the pre-login legal notice on console and VTY sessions."},
    "MGMT.SESSION_TIMEOUT": {"about": "Whether idle management sessions time out.",
        "fix_title": "Set management session timeout", "commands": ["line vty 0 4", "exec-timeout 5 0", "line con 0", "exec-timeout 5 0"],
        "validation": ["show running-config | include exec-timeout"],
        "impact": "Idle admin sessions left open are hijacked from unlocked terminals or via session theft."},
    "MGMT.ENCRYPTED_ONLY": {"about": "Whether management is reachable only over encrypted protocols.",
        "fix_title": "Restrict management to encrypted protocols", "commands": ["line vty 0 4", "transport input ssh", "no ip http server", "ip http secure-server"],
        "validation": ["show running-config | include transport input"],
        "impact": "Any cleartext management path exposes credentials to anyone on the path."},
    "AUDIT.CONFIG_ARCHIVED": {"about": "Whether the running configuration is archived/versioned off-device.",
        "fix_title": "Archive configurations", "commands": ["archive", "path tftp://10.0.0.50/$h-", "write-memory"],
        "validation": ["show archive"],
        "impact": "Unarchived configs mean unauthorized changes and drift go undetected."},
    "MONITORING.NETFLOW": {"about": "Whether flow telemetry is exported for monitoring.",
        "fix_title": "Enable NetFlow export", "commands": ["ip flow-export version 9", "ip flow-export destination 10.0.0.60 9996", "interface GigabitEthernet0/0", "ip flow ingress"],
        "validation": ["show ip flow export"],
        "impact": "Without flow telemetry, lateral movement and exfiltration stay invisible."},
    "DOS.PROTECTION": {"about": "Whether control-plane/DOS protections (CoPP, rate limiting) are configured.",
        "fix_title": "Enable control-plane protection", "commands": ["control-plane", "service-policy input COPP-POLICY"],
        "validation": ["show policy-map control-plane"],
        "impact": "Unprotected control plane can be knocked offline with a traffic flood, losing management."},
    "CONSOLE.SECURED": {"about": "Whether the console port requires authentication and times out.",
        "fix_title": "Secure the console port", "commands": ["line con 0", "password <strong>", "login", "exec-timeout 5 0"],
        "validation": ["show running-config | include line con"],
        "impact": "An open console gives password-free physical takeover of the device."},
    "VTY.ACL_APPLIED": {"about": "Whether VTY lines restrict sources by access-class.",
        "fix_title": "Apply ACL to VTY lines", "commands": ["ip access-list standard MGMT-ALLOW", "permit 10.0.0.0 0.0.0.255", "line vty 0 4", "access-class MGMT-ALLOW in"],
        "validation": ["show running-config | include access-class"],
        "impact": "VTY without an ACL accepts logins from any reachable host."},
    "VTY.TIMEOUT_SET": {"about": "Whether VTY lines have an exec timeout.",
        "fix_title": "Set VTY exec timeout", "commands": ["line vty 0 4", "exec-timeout 5 0"],
        "validation": ["show running-config | include exec-timeout"],
        "impact": "VTY sessions without timeout persist after the admin walks away."},
    "DHCP.SNOOPING": {"about": "Whether DHCP snooping blocks rogue DHCP servers.",
        "fix_title": "Enable DHCP snooping", "commands": ["ip dhcp snooping", "ip dhcp snooping vlan 10", "interface GigabitEthernet0/1", "ip dhcp snooping trust"],
        "validation": ["show ip dhcp snooping"],
        "impact": "Rogue DHCP can redirect clients through an attacker gateway."},
    "PORT_SECURITY.ENABLED": {"about": "Whether switch port-security limits MACs per port.",
        "fix_title": "Enable port security", "commands": ["interface GigabitEthernet0/1", "switchport port-security", "switchport port-security maximum 2", "switchport port-security violation restrict"],
        "validation": ["show port-security"],
        "impact": "Open ports allow CAM flooding and silent traffic interception."},
    "STP.BPDU_GUARD": {"about": "Whether BPDU guard blocks STP manipulation on edge ports.",
        "fix_title": "Enable BPDU guard on edge ports", "commands": ["spanning-tree portfast bpduguard default", "interface GigabitEthernet0/1", "spanning-tree bpduguard enable"],
        "validation": ["show spanning-tree summary"],
        "impact": "Without BPDU guard an attacker can become STP root and intercept VLAN traffic."},
    "CDP.DISABLED_EDGE": {"about": "Whether CDP/LLDP is disabled on untrusted edge ports.",
        "fix_title": "Disable discovery on edge ports", "commands": ["interface GigabitEthernet0/1", "no cdp enable", "no lldp transmit", "no lldp receive"],
        "validation": ["show cdp interface"],
        "impact": "Discovery protocols leak device model, IPs and topology to anyone plugged into the edge."},
    "DNS.LOOKUP_DISABLED": {"about": "Whether CLI DNS lookup is disabled.",
        "fix_title": "Disable CLI DNS lookup", "commands": ["no ip domain-lookup"],
        "validation": ["show running-config | include domain-lookup"],
        "impact": "CLI typos trigger DNS queries that hang sessions and can leak intent to rogue resolvers."},
    "AAA.ACCOUNTING": {"about": "Whether AAA accounting records admin activity.",
        "fix_title": "Enable AAA accounting", "commands": ["aaa accounting exec default start-stop group tacacs+", "aaa accounting commands 15 default start-stop group tacacs+"],
        "validation": ["show running-config | include aaa accounting"],
        "impact": "Without accounting there is no record of who executed which commands — incidents become unattributable."},
    "AAA.TACACS_CONFIGURED": {"about": "Whether TACACS+ authentication servers are configured.",
        "fix_title": "Point AAA at TACACS+ servers", "commands": ["aaa new-model", "tacacs server CORP", "address ipv4 10.0.0.10", "aaa authentication login default group tacacs+ local"],
        "validation": ["show running-config | include tacacs"],
        "impact": "Without central authentication, admin access depends on shared local passwords with no per-user control."},
    "AAA.RADIUS_CONFIGURED": {"about": "Whether RADIUS authentication servers are configured.",
        "fix_title": "Point AAA at RADIUS servers", "commands": ["aaa new-model", "radius-server host 10.0.0.11 key <strong>", "aaa authentication login default group radius local"],
        "validation": ["show running-config | include radius"],
        "impact": "Without central authentication, disabling one admin means touching every device."},
    "HTTPS.ENABLED": {"about": "Whether HTTPS management is enabled.",
        "fix_title": "Serve management over HTTPS", "commands": ["no ip http server", "ip http secure-server"],
        "validation": ["show running-config | include ip http"],
        "impact": "Cleartext HTTP management exposes admin credentials to network sniffing."},
    "BANNER.EXEC_SET": {"about": "Whether an EXEC banner warns against unauthorized use.",
        "fix_title": "Configure EXEC banner", "commands": ["banner exec ^", "Authorized use only. All activity is monitored.", "^"],
        "validation": ["show running-config | include banner"],
        "impact": "Missing banners weaken legal standing when prosecuting unauthorized access."},
    "SERVICE.PAD_DISABLED": {"about": "Whether the PAD service is disabled.",
        "fix_title": "Disable PAD service", "commands": ["no service pad"],
        "validation": ["show running-config | include service pad"],
        "impact": "PAD gives an unneeded remote access path into the device."},
    "SERVICE.FINGER_DISABLED": {"about": "Whether the finger service is disabled.",
        "fix_title": "Disable finger service", "commands": ["no ip finger", "no service finger"],
        "validation": ["show running-config | include finger"],
        "impact": "Finger discloses logged-in usernames, aiding targeted password attacks."},
    "IP.DIRECTED_BROADCAST_DISABLED": {"about": "Whether directed broadcast is disabled on interfaces.",
        "fix_title": "Disable directed broadcast", "commands": ["interface GigabitEthernet0/0", "no ip directed-broadcast"],
        "validation": ["show running-config interface"],
        "impact": "Directed broadcast enables Smurf-style traffic amplification attacks."},
    "URPF.ENABLED": {"about": "Whether unicast reverse-path forwarding drops spoofed packets.",
        "fix_title": "Enable uRPF on edge interfaces", "commands": ["interface GigabitEthernet0/0", "ip verify unicast source reachable-via rx"],
        "validation": ["show ip interface GigabitEthernet0/0 | include RPF"],
        "impact": "Without uRPF, spoofed-source attack traffic enters unchallenged."},
    "SNMP.ACL_RESTRICTED": {"about": "Whether SNMP community access is restricted by ACL.",
        "fix_title": "Restrict SNMP by ACL", "commands": ["ip access-list standard SNMP-ALLOW", "permit 10.0.0.0 0.0.0.255", "snmp-server community <name> RO SNMP-ALLOW"],
        "validation": ["show running-config | include snmp-server community"],
        "impact": "SNMP strings reachable from anywhere are probed and abused at scale."},
    "LOGGING.BUFFERED": {"about": "Whether local buffered logging is configured.",
        "fix_title": "Configure buffered logging", "commands": ["logging buffered 16384 informational"],
        "validation": ["show logging | include Buffer"],
        "impact": "Without a local buffer, evidence is lost whenever the collector is unreachable."},
    "NTP.SOURCE_SET": {"about": "Whether the NTP source interface is pinned.",
        "fix_title": "Pin NTP source interface", "commands": ["ntp source Loopback0"],
        "validation": ["show running-config | include ntp source"],
        "impact": "Floating NTP sources make time sync unstable and harder to audit."},
    "SSH.MACS_STRONG": {"about": "Whether SSH offers only strong message-authentication codes.",
        "fix_title": "Restrict SSH to strong MACs", "commands": ["ip ssh server algorithm mac hmac-sha2-256 hmac-sha2-512"],
        "validation": ["show ip ssh"],
        "impact": "Weak SSH MACs let attackers tamper with admin sessions undetected."},
}


def _is_placeholder_desc(desc: str) -> bool:
    d = (desc or "").strip()
    return not d or d.startswith("OSCAL-normalized")


def _condition_leaves(cond: object) -> list:
    """Flatten {all:[...]}/{any:[...]}/single condition into leaf list."""
    if not isinstance(cond, dict):
        return []
    if "all" in cond and isinstance(cond["all"], list):
        out: list = []
        for c in cond["all"]:
            out.extend(_condition_leaves(c))
        return out
    if "any" in cond and isinstance(cond["any"], list):
        out: list = []
        for c in cond["any"]:
            out.extend(_condition_leaves(c))
        return out
    if cond.get("property"):
        return [cond]
    return []


def _fmt_val(v: object) -> str:
    if v is None:
        return "not set"
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


@compliance_router.get("/{audit_id}/controls")
def compliance_controls(audit_id: str):
    _audit_cols(audit_id, ["audit_id"])
    # NOTE: findings keeps only typed key columns + evidence/risk/remediation
    # JSONB natively; frameworks lives inside the `data` JSONB blob
    # (see persist._SCHEMA) so it must be projected from `data`.
    # Falls back to full-record reads on older DBs without the `data` column.
    try:
        rows = db.select("findings", ["finding_id", "control_id", "title", "status",
                                      "severity", "evidence", "remediation",
                                      "data->'frameworks' AS frameworks",
                                      "risk", "confidence"],
                         limit=500, audit_id=audit_id, engine="compliance")
    except Exception:
        rows = [{k: rec.get(k) for k in ("finding_id", "control_id", "title", "status",
                                         "severity", "evidence", "remediation",
                                         "frameworks", "risk", "confidence")}
                for rec in db.find("findings", audit_id=audit_id, engine="compliance")][:500]
    # Enrich with Control KB description/references plus synthesized
    # per-property explanations so the UI never renders blanks:
    # WHAT (description) / WHY (evidence-grounded) / HOW (fix) / IMPACT.
    try:
        okf = okf_layer()
        ckb = okf["ckb"].controls if hasattr(okf["ckb"], "controls") else {}
        rem_index = okf["rem"].index if hasattr(okf["rem"], "index") else {}
    except Exception:
        ckb, rem_index = {}, {}
    items = []
    for f in rows:
        cid = f.get("control_id", "")
        ctl = ckb.get(cid) if isinstance(ckb, dict) else None
        desc = ""
        refs: list = []
        cond: object = {}
        if ctl is not None:
            try:
                desc = ctl.description if isinstance(ctl.description, str) else str(ctl.description)
                refs = list(ctl.references or [])
                cond = ctl.condition or {}
            except Exception:
                pass
        leaves = _condition_leaves(cond)
        status = str(f.get("status", "UNKNOWN")).upper()
        ev = f.get("evidence") or {}
        if not isinstance(ev, dict):
            ev = {"observed_value": ev}
        prop = str(ev.get("property") or (leaves[0].get("property") if leaves else "") or "")
        guide = _PROPERTY_GUIDE.get(prop, {})
        observed = ev.get("observed_value", ev.get("observed", None))
        expected = ev.get("expected_value", ev.get("expected", None))
        if expected is None and leaves:
            expected = leaves[0].get("value", None)
        missing = observed is None
        observed_display = "Not found in configuration" if missing else _fmt_val(observed)
        expected_display = _fmt_val(expected)

        # WHAT — KB description, else synthesized from the actual condition.
        if _is_placeholder_desc(desc):
            if guide.get("about"):
                desc = f"{guide['about']} This device was checked for {prop} (expected {expected_display})."
            elif leaves:
                desc = (f"Requires {', '.join(l.get('property', '') for l in leaves)} "
                        f"to be {expected_display} per {f.get('title') or cid}.")
            else:
                desc = str(f.get("title") or cid)

        # WHY — grounded in observed vs expected, with UNKNOWN handled distinctly.
        # NOT_APPLICABLE controls were never executed (out of platform scope).
        op = str(ev.get("operator") or (leaves[0].get("operator") if leaves else "EQUALS") or "EQUALS")
        if status == "NOT_APPLICABLE":
            scope = ((ctl.applies_to if ctl is not None else {}) or {})
            want = ", ".join([*(scope.get("vendors") or []), *(scope.get("platforms") or [])]) or "its listed platforms"
            why = (f"Skipped before evaluation: this control only applies to {want}, "
                   f"so it was not checked against this device and does not affect the score.")
        elif status == "PASS":
            why = (f"Requirement met: {prop} is {observed_display} "
                   f"(required {expected_display}, {op}).")
        elif status == "UNKNOWN" or missing:
            why = (f"No evidence for {prop or 'this setting'} was found in the uploaded configuration, "
                   f"so compliance could not be verified. Expected {expected_display}. "
                   f"This usually means the setting is absent or the parser has no mapping for those lines.")
        else:
            why = (f"Observed {prop} = {observed_display} does not satisfy required "
                   f"{expected_display} ({op}).")

        # HOW — KB remediation when present, else per-property fix (never blank).
        rem_detail = f.get("remediation") or {}
        fix_title, fix_cmds, fix_val, fix_rb = "", [], ["show running-config"], []
        if isinstance(rem_detail, dict):
            d = rem_detail.get("detail") if isinstance(rem_detail.get("detail"), dict) else rem_detail
            if isinstance(d, dict):
                fix_title = str(d.get("title") or rem_detail.get("title") or "")
                if isinstance(d.get("commands"), list):
                    fix_cmds = [str(x) for x in d["commands"]]
                if isinstance(d.get("validation"), list):
                    fix_val = [str(x) for x in d["validation"]]
                if isinstance(d.get("rollback"), list):
                    fix_rb = [str(x) for x in d["rollback"]]
        if not fix_cmds:
            kb_entry = rem_index.get(cid, {}) if isinstance(rem_index, dict) else {}
            vendors = (kb_entry.get("vendors") or {}) if isinstance(kb_entry, dict) else {}
            vend = next(iter(vendors.values()), {}) if vendors else {}
            if vend:
                fix_title = fix_title or str(vend.get("title") or "")
                fix_cmds = [str(x) for x in (vend.get("commands") or [])]
                fix_val = [str(x) for x in (vend.get("validation") or [])] or fix_val
                fix_rb = [str(x) for x in (vend.get("rollback") or [])]
        if not fix_cmds and guide:
            fix_title = fix_title or str(guide.get("fix_title") or "")
            fix_cmds = [str(x) for x in guide.get("commands", [])]
            fix_val = [str(x) for x in guide.get("validation", [])] or fix_val
        if not fix_cmds:
            # Multi-leaf fallback: one verification command per property.
            fix_cmds = [f"Configure {l.get('property')} to {l.get('value')}" for l in leaves] or [
                f"Configure {prop or 'this setting'} to {expected_display}"]
            fix_title = fix_title or f"Bring {prop or 'setting'} to the required value"
        fix = {"title": fix_title, "commands": fix_cmds, "validation": fix_val, "rollback": fix_rb}
        if status == "NOT_APPLICABLE":
            fix = {"title": "Not applicable — no fix needed",
                   "commands": [], "validation": [], "rollback": []}

        # IMPACT — property-specific consequence, severity only as a tail.
        # PASS rows are proof of compliance, not open problems: say so instead
        # of warning about an attack that is currently blocked.
        sev = str(f.get("severity", "MEDIUM")).upper()
        risk = f.get("risk") or {}
        score = (risk.get("risk_score") if isinstance(risk, dict) else None)
        prio = (risk.get("priority") if isinstance(risk, dict) else None)
        if status == "PASS":
            impact = (f"Control is passing — {prop or 'this setting'} is {observed_display} as required, "
                      f"so there is no open risk from this item. The {sev.title()} severity would apply "
                      f"only if the setting regresses.")
        elif status == "NOT_APPLICABLE":
            impact = ("No action — this control does not apply to this device's platform, "
                      "so it was skipped and excluded from the score.")
        else:
            base_impact = str(guide.get("impact") or "").strip()
            if not base_impact:
                base_impact = "Leaving this misconfigured keeps the flagged attack surface open."
            tail = f" Severity {sev.title()}"
            if prio or score is not None:
                tail += f" (risk {prio or '—'}" + (f", score {score}" if score is not None else "") + ")"
            if status == "UNKNOWN" or missing:
                impact = (f"Unverified — no evidence for {prop or 'this setting'} was found, "
                          f"so this risk is unconfirmed. "
                          f"If the setting is truly absent: {base_impact}{tail}.")
            else:
                impact = f"{base_impact}{tail}."

        items.append({"finding_id": f.get("finding_id"), "control_id": cid,
                      "title": f.get("title"), "description": desc,
                      "status": f.get("status"), "severity": f.get("severity"),
                      "evidence": f.get("evidence"),
                      "evidence_display": {"property": prop or "—", "observed": observed_display,
                                           "expected": expected_display, "operator": op,
                                           "missing": missing},
                      "why_explanation": why,
                      "remediation": rem_detail, "fix": fix,
                      "impact_statement": impact,
                      "frameworks": f.get("frameworks", {}),
                      "risk": f.get("risk", {}), "confidence": f.get("confidence", 1.0),
                      "references": refs})
    return cfg.ok({"audit_id": audit_id, "items": items})


@vuln_router.get("/cves")
def cve_db(cve_id: Optional[str] = None, vendor: Optional[str] = None,
           product: Optional[str] = None, severity: Optional[str] = None):
    kb = cve_layer()["kb"]().load()
    items = kb.records
    if cve_id:
        items = [r for r in items if r.get("cve_id") == cve_id]
    if vendor:
        items = [r for r in items if vendor.lower() in str(r).lower()]
    if product:
        items = [r for r in items if product.lower() in str(r).lower()]
    if severity:
        items = [r for r in items if str((r.get("cvss") or {}).get("severity", "")).upper() == severity.upper()]
    return cfg.ok({"total": len(items), "items": items[:200]})


@vuln_router.get("/kb/status")
def kb_status():
    """Threat-intel health: real NVD records vs synthetic seeds."""
    kb = cve_layer()["kb"]().load()
    seeds = sum(1 for r in kb.records if r.get("source") == "OKF-SEED-SYNTHETIC")
    nvd = sum(1 for r in kb.records if r.get("source") == "NVD")
    try:
        import json as _json
        meta = _json.loads((cfg.OKF_DIR / "knowledge" / "vulnerability" / "meta.json").read_text())
    except Exception:
        meta = {}
    return cfg.ok({"records": len(kb.records), "seed_records": seeds, "nvd_records": nvd,
                   "real_world": nvd > 0, "meta": meta,
                   "note": "Production matching uses NVD records only; seed records "
                           "are offline test fixtures and never matched."})


@vuln_router.post("/sync")
def cve_sync(body: dict):
    job_id = store.nid("CVE-SYNC")
    db.save("jobs", {"job_id": job_id, "kind": "cve_sync", "status": "RUNNING",
                     "created_at": store.now()})
    try:
        # Multi-product bootstrap: {"products": ["cisco ios xe", {vendor,product}...]}
        keywords: list = []
        for p in body.get("products") or []:
            if isinstance(p, dict):
                q = f"{p.get('vendor', '')} {p.get('product', '')}".strip()
            else:
                q = str(p or "").strip()
            if q and q not in keywords:
                keywords.append(q)
        data = cve_layer()["sync_now"](body.get("keyword"),
                                        int(body.get("pages", 1)),
                                        min(int(body.get("results_per_page", 200)), 2000),
                                        keywords=keywords or None,
                                        drop_seeds=bool(body.get("drop_seeds", False)))
        job = db.update("jobs", job_id, {"status": "COMPLETED", "result": data})
    except Exception as e:
        job = db.update("jobs", job_id, {"status": "FAILED", "error": str(e)})
    assert job is not None
    return cfg.ok({"job_id": job_id, "status": job["status"]})


@vuln_router.get("/sync/{job_id}")
def cve_sync_status(job_id: str):
    job = db.get("jobs", job_id)
    if not job or job.get("kind") != "cve_sync":
        raise HTTPException(404, "Sync job not found")
    return cfg.ok(job)


class BlastBody(BaseModel):
    cve_id: str
    assets: list = []


@vuln_router.post("/blast-radius")
def blast_radius(body: BlastBody):
    """New CVE → which assets are affected (cve_okf §23)."""
    kb = cve_layer()["kb"]().load()
    rec = next((r for r in kb.records if r.get("cve_id") == body.cve_id), None)
    if not rec:
        raise HTTPException(404, f"CVE {body.cve_id} not in local KB")
    return cfg.ok(cve_layer()["assets_affected"](rec, body.assets))


@vuln_router.get("/{audit_id}")
def vulns_for_audit(audit_id: str):
    rec = _audit_cols(audit_id, ["cve"])
    matches = (rec.get("cve") or {}).get("matches", [])
    unresolved = (rec.get("cve") or {}).get("unresolved", [])
    # Correlate raw CVE matches with unified findings so the UI can link
    # each row to its finding detail (severity + finding_id live there).
    try:
        rows = db.select("findings", ["finding_id", "evidence",
                                         "data->'source' AS source"],
                         limit=500, audit_id=audit_id, engine="cve")
    except Exception:
        try:
            rows = [{k: rec.get(k) for k in ("finding_id", "evidence", "source")}
                    for rec in db.find("findings", audit_id=audit_id, engine="cve")][:500]
        except Exception:
            rows = []
    by_key = {}
    by_cpe = {}
    by_observed = {}
    by_cve: dict = {}
    for f in rows:
        src = f.get("source") or {}
        ev = f.get("evidence") or {}
        by_key[(src.get("cve"), ev.get("observed"))] = f.get("finding_id")
        if ev.get("cpe"):
            by_cpe.setdefault(ev.get("cpe"), f.get("finding_id"))
        if ev.get("observed"):
            by_observed.setdefault(ev.get("observed"), f.get("finding_id"))
        if src.get("cve"):
            by_cve.setdefault(src.get("cve"), f.get("finding_id"))
    items = []
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for m in matches:
        m = dict(m)
        # Same severity rule as audit_service: known CVSS severity or UNKNOWN.
        s = str((m.get("cvss") or {}).get("severity") or "UNKNOWN").upper()
        if s not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            s = "UNKNOWN"
        m["severity"] = s
        fid = by_key.get((m.get("cve_id"), m.get("installed_version")))
        if not fid and m.get("cpe"):
            fid = by_cpe.get(m.get("cpe"))
        if not fid and m.get("installed_version"):
            fid = by_observed.get(m.get("installed_version"))
        if not fid and m.get("cve_id"):
            fid = by_cve.get(m.get("cve_id"))
        m["finding_id"] = fid
        items.append(m)
        sev[s.lower()] += 1
    return cfg.ok({"audit_id": audit_id, "summary": {"total": len(items), **sev},
                   "unresolved": unresolved, "items": items})


@vuln_router.get("/{audit_id}/{finding_id}")
def vuln_detail(audit_id: str, finding_id: str):
    f = db.get("findings", finding_id)
    if not f or f.get("audit_id") != audit_id:
        raise HTTPException(404, "Finding not found")
    f = dict(f)
    src = f.get("source") or {}
    ev = f.get("evidence") or {}
    if not isinstance(src, dict):
        src = {}
    if not isinstance(ev, dict):
        ev = {"observed": ev}
    cve_id = src.get("cve")
    observed = ev.get("observed")
    # The audit's stored CVE match carries cvss / fixed version / matched rule.
    match: dict = {}
    audit_vendor = ""
    try:
        rec = _audit_cols(audit_id, ["cve", "vendor"])
        audit_vendor = str((rec.get("vendor") or {}).get("vendor_id") or "")
        stored = (rec.get("cve") or {}).get("matches", []) or []
        for m in stored:
            if cve_id and m.get("cve_id") == cve_id and m.get("installed_version") == observed:
                match = m
                break
        if not match and cve_id:
            for m in stored:
                if m.get("cve_id") == cve_id:
                    match = m
                    break
    except Exception:
        match = {}
    # Authoritative KB record: description, CWE, references, canonical CVSS.
    kb_rec: dict = {}
    if cve_id:
        try:
            kb = cve_layer()["kb"]().load()
            kb_rec = next((r for r in kb.records if r.get("cve_id") == cve_id), {}) or {}
        except Exception:
            kb_rec = {}
    kb_cvss = kb_rec.get("cvss") or {}
    m_cvss = match.get("cvss") or {}
    if not isinstance(kb_cvss, dict):
        kb_cvss = {}
    if not isinstance(m_cvss, dict):
        m_cvss = {}
    product = match.get("product") or "—"
    installed = match.get("installed_version") or observed or "—"
    # The CPE row must describe the DEVICE, not the vulnerable entry: prefer
    # the installed CPE recorded at correlation time.
    cpe = match.get("installed_cpe") or match.get("cpe") or ev.get("cpe") or "—"
    fixed = match.get("fixed_version") or (f.get("remediation") or {}).get("fixed_version")
    status = match.get("status") or f.get("status") or "UNKNOWN"
    rule = match.get("matched_rule") or {}
    if not isinstance(rule, dict):
        rule = {}
    if not rule:
        # Legacy rows stored matched_rule=None on misses: backfill ONLY from a
        # KB entry naming the SAME product — never the CVE's first entry,
        # which for multi-product CVEs is often another product's range.
        try:
            from src.cve.cpe_resolver import canonical as _canon
            want = _canon(audit_vendor, product if product != "—" else "")
            for aff in kb_rec.get("affected") or []:
                if _canon(aff.get("vendor", ""), aff.get("product", "")) == want:
                    rule = ((aff.get("affected_versions") or [{}])[0]) or {}
                    break
        except Exception:
            rule = {}
    refs: list = []
    for r in list(match.get("references") or []) + list(kb_rec.get("references") or []):
        s = r if isinstance(r, str) else (r.get("url") if isinstance(r, dict) else str(r))
        if s and s not in refs:
            refs.append(s)
    cwe = kb_rec.get("cwe", [])
    # Actionable remedy grounded in the actual version data.
    steps: list = []
    if status == "VULNERABLE":
        if fixed:
            steps.append(f"Upgrade {product} from {installed} to {fixed} (or a later fixed release).")
        else:
            steps.append(f"No fixed release is recorded for {cve_id} — follow the vendor "
                         f"security advisory for {product}.")
        steps.append("Restart/reload the affected service if the vendor requires it, "
                     "then re-run this audit to verify the finding clears.")
    elif status == "NOT_AFFECTED":
        steps.append(f"No action required — {product} {installed} is outside the affected range.")
    else:
        steps.append("Assessment is inconclusive — confirm the installed version and re-run the audit.")
    detail = {**f,
              "cve_id": cve_id or f.get("finding_id"),
              "description": kb_rec.get("description") or match.get("reason") or f.get("title"),
              "status": status,
              "severity": f.get("severity") or m_cvss.get("severity") or kb_cvss.get("severity") or "UNKNOWN",
              "product": product, "installed_version": installed, "cpe": cpe,
              "fixed_version": fixed,
              "cvss": {"score": m_cvss.get("score", kb_cvss.get("base_score")),
                       "severity": m_cvss.get("severity", kb_cvss.get("severity")),
                       "vector": m_cvss.get("vector", kb_cvss.get("vector"))},
              "cwe": cwe,
              "affected_range": {"start": rule.get("start"), "end": rule.get("end"),
                                 "start_inclusive": rule.get("start_inclusive", True),
                                 "end_inclusive": rule.get("end_inclusive", True)},
              "matched_rule": match.get("matched_rule"),
              "confidence": match.get("confidence", f.get("confidence")),
              "references": refs,
              "remediation": {"available": bool(fixed or status == "VULNERABLE"),
                              "fixed_version": fixed,
                              "recommendation": steps[0] if steps else "",
                              "steps": steps,
                              "validation": ["Re-run the audit and confirm this finding "
                                             "reports NOT_AFFECTED / PASS."]}}
    return cfg.ok(detail)


@pqc_router.get("/{audit_id}")
def pqc_for_audit(audit_id: str):
    from app.engines import pqc as pqc_eng
    rec = _audit_cols(audit_id, ["pqc"])
    # Normalize so audits stored by older engine versions (legacy string
    # recs, rows without risk/priority) still render with full detail.
    p = pqc_eng.normalize_pqc_payload(rec["pqc"] or {})
    algos = p.get("algorithms", [])
    weak = p.get("weak_algorithms") or [a for a in algos if a.get("pqc_status") == "MIGRATION_REQUIRED"]
    return cfg.ok({"audit_id": audit_id, "readiness_score": p.get("readiness_score"),
                   "readiness": p.get("readiness", p.get("readiness_score")),
                   "readiness_label": p.get("readiness_label"),
                   "counts": p.get("counts", {}),
                   "algorithms": algos,
                   "weak_algorithms": weak,
                   "migration_recommendations": p.get("migration_recommendations", [])})


@analytics_router.get("/{audit_id}")
def analytics_for_audit(audit_id: str):
    rec = _audit_cols(audit_id, ["security"])
    s = rec["security"] or {}
    return cfg.ok({"audit_id": audit_id, "risk_score": s.get("risk_score"),
                   "anomalies": s.get("anomalies", []), "patterns": s.get("patterns", [])})


class FleetBody(BaseModel):
    asset_ids: List[str] = []


@analytics_router.post("/fleet")
def fleet_start(body: FleetBody):
    """Fleet outlier detection: latest Canonical IR per asset → M7 (fit per fleet)."""
    from app.services.integration import m7_fit_fleet, okf_flat_to_m7
    job_id = store.nid("FLEET")
    # Projected read: only what fleet fitting needs (never full audit payloads).
    rows = db.select("audits", ["asset_id", "created_at", "data->'flat_ir' AS flat_ir"], limit=500)
    latest: dict = {}

    def _ts(v: object) -> float:
        try:
            return float(v or 0)
        except (TypeError, ValueError):
            return 0.0

    for a in rows:
        aid = a.get("asset_id")
        if aid in body.asset_ids and (aid not in latest or _ts(a.get("created_at")) > _ts(latest[aid].get("created_at"))):
            latest[aid] = a
    aids = [aid for aid in body.asset_ids if aid in latest]
    feats = [okf_flat_to_m7(latest[aid].get("flat_ir", {})) for aid in aids]
    m7 = m7_fit_fleet(feats) if feats else {"method": "none", "outliers": [], "labels": []}
    devices = [{"asset_id": aid, "outlier": bool(m7["outliers"][i]) if i < len(m7["outliers"]) else False,
                "cluster": (m7.get("labels") or [0])[i] if i < len(m7.get("labels") or []) else 0}
               for i, aid in enumerate(aids)]
    db.save("jobs", {"job_id": job_id, "kind": "fleet", "status": "COMPLETED",
                     "method": m7.get("method"), "assets": len(aids),
                     "outliers": sum(1 for d in devices if d["outlier"]),
                     "devices": devices, "created_at": store.now()})
    return cfg.ok({"job_id": job_id, "status": "COMPLETED"})


@analytics_router.get("/fleet/{job_id}")
def fleet_status(job_id: str):
    job = db.get("jobs", job_id)
    if not job or job.get("kind") != "fleet":
        raise HTTPException(404, "Fleet job not found")
    return cfg.ok(job)
