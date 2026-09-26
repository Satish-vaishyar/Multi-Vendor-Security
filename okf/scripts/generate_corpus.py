"""Synthetic configuration corpus generator (OKF-D1).

Profiles: secure / insecure / edge / unknown. Vendors: cisco, juniper,
fortinet, paloalto, arista, unknown. Device-level ground truth in manifest.json.

Usage:
  python scripts/generate_corpus.py --per-vendor 5 --out data/corpus      # quick
  python scripts/generate_corpus.py --per-vendor 500 --out data/corpus    # full ~3000
"""
from __future__ import annotations
import argparse
import hashlib
import json
import random
from pathlib import Path

TEMPLATES = {
    "cisco": {
        "ssh_secure": "ip ssh version 2\nip ssh time-out 60\nip ssh authentication-retries 3",
        "ssh_weak": "ip ssh version 1",
        "telnet_on": "line vty 0 4\n transport input telnet",
        "telnet_off": "line vty 0 4\n transport input ssh\n access-class MGMT-IN in",
        "http_on": "ip http server", "http_off": "no ip http server\nip http secure-server",
        "snmp_bad": "snmp-server community public RO", "snmp_good": "snmp-server group NETADMIN v3 priv",
        "log_on": "logging host 10.0.0.99\nservice timestamps log datetime",
        "log_off": "no logging",
        "ntp_on": "ntp server 10.0.0.5\nntp authenticate", "ntp_off": "no ntp",
        "aaa_on": "aaa new-model\ntacacs-server host 10.0.0.10\nlogin block-for 120 attempts 3 within 60",
        "aaa_off": "no aaa new-model",
        "crypto_bad": "crypto key generate rsa modulus 1024", "crypto_good": "crypto key generate rsa modulus 2048",
        "extra_secure": "service password-encryption\nenable secret 9 $9$hashed\nno ip source-route\nno ip proxy-arp\nip dhcp snooping\nbanner motd # Authorized use only #",
        "extra_edge": "!",
    },
    "juniper": {
        "ssh_secure": "set system services ssh protocol-version v2",
        "ssh_weak": "set system services ssh protocol-version v1",
        "telnet_on": "set system services telnet", "telnet_off": "delete system services telnet",
        "http_on": "set system services web-management http",
        "http_off": "delete system services web-management http",
        "snmp_bad": "set snmp community public authorization read-only",
        "snmp_good": "set snmp v3 usm local-engine user admin authentication-sha authentication-password *** privacy-aes128",
        "log_on": "set system syslog host 10.0.0.99 any any", "log_off": "delete system syslog",
        "ntp_on": "set system ntp server 10.0.0.5", "ntp_off": "delete system ntp",
        "aaa_on": "set system authentication-order tacplus", "aaa_off": "delete system tacplus-server",
        "crypto_bad": "set security ike proposal weak dh-group1", "crypto_good": "set security ike proposal strong dh-group14",
        "extra_secure": "set system login password format sha512\nset system services ssh no-passwords",
        "extra_edge": "# edge: empty stanza",
    },
    "fortinet": {
        "ssh_secure": "set admin-https-redirect enable\nset ssh-port 22",
        "ssh_weak": "set admin-telnet enable",
        "telnet_on": "set admin-telnet enable", "telnet_off": "set admin-telnet disable",
        "http_on": "set admin-http enable", "http_off": "set admin-http disable",
        "snmp_bad": "set snmp-community public", "snmp_good": "set snmpv3 enable",
        "log_on": "set syslog-server 10.0.0.99", "log_off": "unset syslog-server",
        "ntp_on": "set ntp-server 10.0.0.5", "ntp_off": "unset ntp-server",
        "aaa_on": "set auth-type tacacs+", "aaa_off": "set auth-type local",
        "crypto_bad": "set weak-crypto enable", "crypto_good": "set strong-crypto enable",
        "extra_secure": "set password-policy enable", "extra_edge": "# edge",
    },
}
# paloalto/arista reuse fortinet/cisco shapes with own banner
TEMPLATES["paloalto"] = {**TEMPLATES["fortinet"], "extra_secure": "set deviceconfig password-complexity enable"}
TEMPLATES["arista"] = {**TEMPLATES["cisco"], "extra_secure": TEMPLATES["cisco"]["extra_secure"] + "\nno ip routing-source"}
TEMPLATES["unknown"] = {
    "ssh_secure": "secure-mgmt ssh protocol v2", "ssh_weak": "secure-mgmt ssh protocol v1",
    "telnet_on": "mgmt telnet permit-all", "telnet_off": "mgmt telnet deny",
    "http_on": "web-mgmt plain enable", "http_off": "web-mgmt plain disable",
    "snmp_bad": "telemetry community public", "snmp_good": "telemetry v3 priv-only",
    "log_on": "event-sink remote 10.0.0.99", "log_off": "event-sink none",
    "ntp_on": "time-sync server 10.0.0.5", "ntp_off": "time-sync none",
    "aaa_on": "auth backend tacacs", "aaa_off": "auth backend none",
    "crypto_bad": "cipher-suite legacy", "crypto_good": "cipher-suite modern",
    "extra_secure": "vault lock enable", "extra_edge": "??? malformed (( stanza",
}

SECURE_KEYS = ["ssh_secure", "telnet_off", "http_off", "snmp_good", "log_on", "ntp_on", "aaa_on", "crypto_good", "extra_secure"]
INSECURE_KEYS = ["ssh_weak", "telnet_on", "http_on", "snmp_bad", "log_off", "ntp_off", "aaa_off", "crypto_bad"]


def build_config(vendor: str, profile: str, rng: random.Random) -> str:
    t = TEMPLATES[vendor]
    if profile == "secure":
        keys = list(SECURE_KEYS)
    elif profile == "insecure":
        keys = list(INSECURE_KEYS)
    elif profile == "edge":
        keys = rng.sample(SECURE_KEYS + INSECURE_KEYS, 5) + ["extra_edge"]
    else:  # unknown profile mixes unknown-vendor idioms
        keys = rng.sample(SECURE_KEYS + INSECURE_KEYS, 6)
    lines = [f"! {vendor} {profile} synthetic"]
    for k in keys:
        if rng.random() < 0.12 and profile in ("secure", "insecure"):
            continue  # drop a line -> partially secure edge
        lines.append(t[k])
    if profile == "unknown":
        lines.append("blorp enable hyperflux-mode")
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-vendor", type=int, default=5)
    ap.add_argument("--out", default="data/corpus")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    out = Path(a.out)
    profiles = ["secure", "insecure", "edge", "unknown"]
    manifest = []
    total = 0
    for vendor in TEMPLATES:
        for i in range(a.per_vendor):
            profile = profiles[i % 4] if vendor != "unknown" else "unknown"
            cfg = build_config(vendor, profile, rng)
            d = out / vendor / profile
            d.mkdir(parents=True, exist_ok=True)
            f = d / f"{vendor}_{profile}_{i:04d}.txt"
            f.write_text(cfg, encoding="utf-8")
            manifest.append({"file": str(f.relative_to(out)), "vendor": vendor,
                             "profile": profile,
                             "sha256": hashlib.sha256(cfg.encode()).hexdigest()})
            total += 1
    (out / "manifest.json").write_text(json.dumps(
        {"total": total, "profiles": profiles, "items": manifest}, indent=1), encoding="utf-8")
    print(json.dumps({"total": total, "out": str(out)}))


if __name__ == "__main__":
    main()
