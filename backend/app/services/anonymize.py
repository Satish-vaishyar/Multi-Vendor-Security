"""Make a device configuration safe to share for accuracy testing, WITHOUT changing how it parses.

Customers will not hand over raw configurations. This tool runs on THEIR machine (``python -m app.cli anonymize``):
nothing is uploaded. It keeps the structure the parsers and rules depend on (line order, keywords, masks, 'any' /
0.0.0.0, prefix lengths, algorithms, versions, ACL logic) and replaces what identifies them:

  * secrets and hashes (the shared redaction rules), SNMP communities / keys, pre-shared keys
  * IPv4 / IPv6 addresses (consistently: the same address always maps to the same fake one; private stays private)
  * host names, domain names, user names, e-mail addresses, MAC addresses
  * free text: interface descriptions, ACL remarks, SNMP location/contact, banners (unless ``keep_text``)

The mapping is returned to the caller (written only when asked for) so the customer can translate findings back.
tests/test_anonymize.py proves the vendor and the compliance verdicts of the sample corpus are unchanged by it.
"""
from __future__ import annotations
import hashlib
import hmac
import ipaddress
import re
from typing import Dict, Tuple

from app.core.redact import redact_secrets

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:.])(?=[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:)[0-9A-Fa-f:]{2,39}(?![0-9A-Fa-f:.])")
# Vendor / factory defaults are a SIGNAL the rules look for (default accounts, "public" communities), not an identity:
# anonymising them would change the verdict, so they are kept verbatim.
DEFAULT_USERS = {"admin", "administrator", "root", "cisco", "user", "test", "guest", "manager", "operator", "monitor",
                 "netadmin", "fortinet", "super", "supervisor", "default", "ubnt", "pi", "service", "support"}
DEFAULT_COMMUNITIES = {"public", "private"}
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})\b")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

_HOST_RULES = [
    re.compile(r"^(\s*hostname\s+)(\S+)", re.I),
    re.compile(r"^(\s*set\s+system\s+host-name\s+)(\S+)", re.I),
    re.compile(r"^(\s*host-name\s+)([^\s;]+)", re.I),
    re.compile(r"^(\s*set\s+deviceconfig\s+system\s+hostname\s+)(\S+)", re.I),
    re.compile(r"^(\s*set\s+hostname\s+)\"?([^\"\s]+)\"?", re.I),
]
_DOMAIN_RULES = [
    re.compile(r"^(\s*ip\s+domain[- ]name\s+)(\S+)", re.I),
    re.compile(r"^(\s*(?:set\s+system\s+)?domain-name\s+)([^\s;]+)", re.I),
    re.compile(r"^(\s*set\s+deviceconfig\s+system\s+domain\s+)(\S+)", re.I),
]
_USER = re.compile(r"^(\s*(?:username|set\s+system\s+login\s+user)\s+)\"?([^\s\"]+)\"?", re.I)
_TEXT = re.compile(r"^(\s*(?:description|remark|snmp-server\s+location|snmp-server\s+contact|set\s+system\s+location|"
                   r"set\s+comment|set\s+alias|name)\s+)(.+?)(;?)\s*$", re.I)
_DEFAULT_SNMP_LINE = re.compile(r"^.*snmp-server\s+(?:community\s+(?:public|private)\b|host\s+\S+.*\s(?:public|private)\b).*$", re.I | re.M)
_SNMP_COMM = re.compile(r"^(\s*snmp-server\s+community\s+)(\S+)", re.I)
_BANNER_START = re.compile(r"^\s*banner\s+\w+\s+(\^C|\S)", re.I)


_HASH = re.compile(r'("?)\$([0-9][0-9a-z]?)\$(?!REDACTED)[^\s";{}]+("?)', re.I)
_HASH_TYPE = re.compile(r'("?)\$([0-9][0-9a-z]?)\$')          # $1$..., $5$..., $6$..., $9$..., $2a$...


def _repair(orig: str, red: str) -> str:
    """The shared redaction rules are line-based and know nothing about brace syntax (Junos). Keep the STRUCTURE of the
    original line - a block opener stays a block opener, a terminating ';' stays - and only let the secret go."""
    stripped = orig.rstrip()
    if stripped.endswith("{") or stripped.endswith("}"):
        return orig                                    # a block opener / closer carries no secret value
    t = _HASH_TYPE.search(orig)
    if t and "<REDACTED>" in red:              # the hash TYPE ($1$ = md5-crypt, $9$ = reversible) is a finding, not an identity
        red = red.replace("<REDACTED>", f'{t.group(1)}${t.group(2)}$REDACTED{t.group(1)}', 1)
    code, sep, comment = orig.partition("##")
    if code.rstrip().endswith(";"):
        r_code, r_sep, r_comment = red.partition("##")
        if not r_code.rstrip().endswith(";"):
            red = r_code.rstrip() + ";" + ((" " + r_sep + r_comment) if r_sep else "")
    return red


def _h(salt: str, kind: str, value: str, n: int = 4) -> bytes:
    return hmac.new(salt.encode(), f"{kind}:{value}".encode(), hashlib.sha256).digest()[:n]


def _is_mask(a: ipaddress.IPv4Address) -> bool:
    """Netmask (255.255.255.0) or wildcard (0.0.0.255): syntax, not identity, so it must survive untouched."""
    n = int(a)
    inv = n ^ 0xFFFFFFFF
    is_netmask = n != 0 and (inv & (inv + 1)) == 0
    is_wildcard = n != 0 and (n & (n + 1)) == 0
    return is_netmask or is_wildcard


def anonymize(text: str, salt: str = "", keep_text: bool = False) -> Tuple[str, Dict[str, str]]:
    mapping: Dict[str, str] = {}
    counters = {"host": 0, "domain": 0, "user": 0}

    def named(kind: str, value: str) -> str:
        key = f"{kind}:{value.lower()}"
        if key not in mapping:
            counters[kind] += 1
            mapping[key] = f"{kind}{counters[kind]}" + (".example.invalid" if kind == "domain" else "")
        return mapping[key]

    def v4(m: "re.Match[str]") -> str:
        raw = m.group(0)
        try:
            a = ipaddress.IPv4Address(raw)
        except ValueError:
            return raw
        if a == ipaddress.IPv4Address("0.0.0.0") or a.is_loopback or a == ipaddress.IPv4Address("255.255.255.255") or _is_mask(a):
            return raw
        b = _h(salt, "v4", raw, 3)
        fake = f"10.{b[0]}.{b[1]}.{b[2] or 1}" if a.is_private else f"203.{b[0]}.{b[1]}.{b[2] or 1}"
        mapping[raw] = fake
        return fake

    def v6(m: "re.Match[str]") -> str:
        raw = m.group(0)
        try:
            a = ipaddress.IPv6Address(raw)
        except ValueError:
            return raw
        if a.is_loopback or a.is_unspecified or a.is_link_local or a.is_multicast:
            return raw
        b = _h(salt, "v6", raw, 4)
        fake = f"2001:db8:{b[0]:x}{b[1]:x}::{b[2]:x}{b[3]:x}"
        mapping[raw] = fake
        return fake

    def mac(m: "re.Match[str]") -> str:
        raw = m.group(0)
        b = _h(salt, "mac", raw.lower(), 6)
        fake = ".".join(f"{b[i]:02x}{b[i + 1]:02x}" for i in (0, 2, 4)) if "." in raw else ":".join(f"{x:02x}" for x in b)
        mapping[raw] = fake
        return fake

    keep: Dict[str, str] = {}

    def stash(m: "re.Match[str]") -> str:
        keep[f"@@KEEP{len(keep)}@@"] = m.group(0)
        return list(keep)[-1]

    redacted = redact_secrets(_DEFAULT_SNMP_LINE.sub(stash, text))        # default communities are a finding, not a secret
    for k, v in keep.items():
        redacted = redacted.replace(k, v)
    o_lines, r_lines = text.splitlines(), redacted.splitlines()
    if len(o_lines) == len(r_lines):
        redacted = "\n".join(_repair(o, r) if o != r else o for o, r in zip(o_lines, r_lines))
    redacted = _HASH.sub(lambda m: f"{m.group(1)}${m.group(2)}$REDACTED{m.group(3)}", redacted)   # hash value out, TYPE kept
    out_lines = []
    in_banner = in_banner_end = ""
    for line in redacted.splitlines():
        if in_banner:
            if in_banner in line:
                in_banner_end, in_banner = in_banner, ""
                out_lines.append(in_banner_end)          # a banner is only tracked when text is being removed
            else:
                out_lines.append("<redacted banner text>")
            continue
        b = _BANNER_START.match(line)
        if b and not keep_text:
            delim = b.group(1)
            rest = line[b.end():]
            if delim not in rest:
                in_banner = delim
            out_lines.append(line[:b.end()])
            continue
        for rx in _HOST_RULES:
            m = rx.match(line)
            if m:
                line = m.group(1) + named("host", m.group(2)) + line[m.end():]
                break
        for rx in _DOMAIN_RULES:
            m = rx.match(line)
            if m:
                line = m.group(1) + named("domain", m.group(2)) + line[m.end():]
                break
        m = _USER.match(line)
        if m and m.group(2).lower() not in DEFAULT_USERS:
            line = m.group(1) + named("user", m.group(2)) + line[m.end():]
        m = _SNMP_COMM.match(line)
        if m and m.group(2).lower() not in DEFAULT_COMMUNITIES:
            line = m.group(1) + "community-" + _h(salt, "snmp", m.group(2), 3).hex() + line[m.end():]
        if not keep_text:
            m = _TEXT.match(line)
            if m and m.group(1).strip().lower() != "name":
                body = m.group(2)
                line = m.group(1) + ('"redacted"' if body.startswith('"') else "redacted") + m.group(3)
        line = _EMAIL.sub("user@example.invalid", line)
        line = _MAC.sub(mac, line)
        line = _IPV6.sub(v6, line)
        line = _IPV4.sub(v4, line)
        out_lines.append(line)
    return "\n".join(out_lines) + ("\n" if text.endswith("\n") else ""), mapping
