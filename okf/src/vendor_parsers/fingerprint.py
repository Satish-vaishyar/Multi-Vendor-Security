"""Deterministic vendor/platform/version fingerprinting from structural markers.

These markers are syntax that only one vendor family uses (e.g. FortiOS `config system global`,
Junos `set system host-name` / `system {`, PAN-OS `deviceconfig`, NX-OS `feature ...` + `vdc`).
When one fires with high confidence it overrides the statistical model (M1), which was trained
on synthetic data. Returns platform tokens in the lower-case form the parsers/controls use:
ios, ios-xe, nx-os, eos, junos, fortios, pan-os.
"""
from __future__ import annotations
import re
from typing import Dict, Optional, Tuple

M = re.MULTILINE

_RULES = [
    # (vendor, platform, confidence, regex over whole text)
    ("fortinet", "fortios", 0.99, re.compile(r"^#config-version=FG|^config system global\b|^config system interface\b", M)),
    ("paloalto", "pan-os", 0.99, re.compile(r"^set (deviceconfig|mgt-config|shared|vsys)\b|^[ \t]*deviceconfig\s*\{|<deviceconfig>|<config\s+version=\"[\d.]+\"[^>]*>\s*<mgt-config", M)),
    ("juniper", "junos", 0.97, re.compile(r"^set (system|interfaces|protocols|security|firewall|snmp)\b|^(system|interfaces|protocols|security)\s*\{|^## Last (commit|changed)|^version\s+\d+\.\d+R\d+", M)),
    ("arista", "eos", 0.95, re.compile(r"^management api http-commands|^daemon TerminAttr|^! device: .*EOS|^transceiver qsfp default-mode|^service routing protocols model|^management ssh$", M)),
    ("cisco", "nx-os", 0.97, re.compile(r"^feature (telnet|ssh|bgp|ospf|nxapi|tacacs\+|interface-vlan|lacp|vpc|lldp)\b|^vdc \S+ id \d+|^version \d+\.\d+\(\d+[a-z]?\)", M)),
    ("cisco", "ios-xe", 0.9, re.compile(r"^version 1[67]\.\d+|^platform qfp|^license boot level|IOS[ -]XE", M)),
    ("cisco", "ios", 0.8, re.compile(r"^service timestamps|^enable (secret|password)|^line vty \d|^interface (Fast|Gigabit)?Ethernet\d", M)),
]

# Gaps between a platform name and its version are BOUNDED ({0,N}): an open-ended `[^\d]*` / `.*` is quadratic when a
# 5 MB config repeats the platform word and contains no digits (regex DoS) - see docs/SECURITY_REVIEW.md PT-18.
_VERSIONS = [
    ("fortinet", re.compile(r"^#config-version=\w+-(\d+\.\d+\.\d+)", M)),
    ("paloalto", re.compile(r"<config\s+version=\"(\d+\.\d+\.\d+)\"|pan-?os[^\d]{0,40}(\d+\.\d+[\.\d\w\-]*)", re.I)),
    ("juniper", re.compile(r"^[ \t]*(?:set\s+)?version\s+(\d+\.\d+R\d+[\w.\-]*)|junos[^\d]{0,40}(\d+\.\d+R\d+[\w.\-]*)", re.I | re.M)),
    ("arista", re.compile(r"EOS-(\d+\.\d+\.\d+[A-Za-z]?)|eos[^\d]{0,40}(\d+\.\d+\.\d+[A-Za-z]?)", re.I)),
    ("cisco", re.compile(r"^version\s+(\d+\.\d+\(\d+[a-z]?\))|ios[ -]?xe\s+software.{0,200}?version\s+(\d+\.\d+\.\d+)|^version\s+(\d+\.\d+[\.\w\-]*)", re.I | re.M)),
]


def fingerprint(text: str) -> Optional[Dict[str, object]]:
    """Best structural match, or None when nothing is distinctive."""
    best: Optional[Tuple[float, str, str]] = None
    for vendor, platform, conf, rx in _RULES:
        if rx.search(text):
            if best is None or conf > best[0]:
                best = (conf, vendor, platform)
    if best is None:
        return None
    conf, vendor, platform = best
    # EOS and NX-OS markers can co-exist with IOS-ish lines: NX-OS wins only on its own markers (above order by conf)
    version = None
    for v, rx in _VERSIONS:
        if v == vendor:
            m = rx.search(text)
            if m:
                version = next((g for g in m.groups() if g), None)
            break
    if vendor == "juniper" and re.search(r"^(set )?security (policies|zones|ike|ipsec)\b|^security\s*\{", text, M):
        platform = "junos"                    # SRX shares the Junos grammar; keep one platform token
    return {"vendor": vendor, "platform": platform, "confidence": conf, "version": version}
