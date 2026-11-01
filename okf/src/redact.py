"""Secret redaction for network device configurations.

Used before anything leaves the trust boundary (external LLM calls, reports,
read-only viewers) and for evidence lines persisted with audits. Dependency
free on purpose: both the backend and the OKF LLM gateway import it.

Redaction replaces only the secret VALUE and keeps the keyword/structure, so
a redacted line is still recognisable (e.g. ``snmp-server community <REDACTED> RO``).
"""
from __future__ import annotations
import re
from typing import List, Tuple

PLACEHOLDER = "<REDACTED>"

# Regex DoS notes (docs/SECURITY_REVIEW.md PT-09): a line-anchored rule that starts with `^(\s*` is QUADRATIC on a file
# made of blank lines, because `\s*` also swallows newlines, so every line start rescans the rest of the file
# (40,000 newlines took ~44 s; a 5 MB upload would pin a worker for hours). Leading whitespace is therefore `[ \t]*`.
# The PEM rule is bounded the same way (no unbounded `.*?` that rescans to the end of the text for every BEGIN marker).

# (compiled regex, replacement). Group 1 is kept; the secret is the rest.
_RULES: List[Tuple[re.Pattern, str]] = [
    # Cisco / Arista: enable secret 5 $1$..., enable password X, username u secret 9 X
    (re.compile(r"(?im)^([ \t]*enable[ \t]+(?:secret|password)(?:[ \t]+\d)?[ \t]+)\S+"), r"\1" + PLACEHOLDER),
    (re.compile(r"(?im)^([ \t]*username[ \t]+\S+(?:[ \t]+privilege[ \t]+\d+)?[ \t]+(?:secret|password)(?:[ \t]+\d)?[ \t]+)\S+"),
     r"\1" + PLACEHOLDER),
    # generic "password [7|0|5] VALUE" (line vty / console / key-string / md5)
    (re.compile(r"(?im)^([ \t]*(?:password|secret)[ \t]+(?:\d[ \t]+)?)\S+"), r"\1" + PLACEHOLDER),
    # BGP / routing peer passwords: "neighbor 203.0.113.1 password 7 045802150C2E1D1C5A" (type 7 is reversible)
    (re.compile(r"(?im)(\bneighbor[ \t]+\S+[ \t]+password[ \t]+(?:\d[ \t]+)?)\S+"), r"\1" + PLACEHOLDER),
    (re.compile(r"(?im)(\bkey-string\s+(?:\d\s+)?)\S+"), r"\1" + PLACEHOLDER),
    (re.compile(r"(?im)(\bmessage-digest-key\s+\d+\s+md5\s+(?:\d\s+)?)\S+"), r"\1" + PLACEHOLDER),
    (re.compile(r"(?im)(\bauthentication-key\s+(?:\d\s+)?)\S+"), r"\1" + PLACEHOLDER),
    # SNMP communities / v3 keys
    (re.compile(r"(?im)(\bsnmp-server\s+community\s+)\S+"), r"\1" + PLACEHOLDER),
    (re.compile(r"(?im)(\bsnmp-server\s+host\s+\S+\s+(?:version\s+\S+\s+)?)\S+"), r"\1" + PLACEHOLDER),
    (re.compile(r"(?im)(\bsnmp-server\s+user\s+\S+\s+\S+\s+v3\s+(?:auth\s+\S+\s+)?)\S+"),
     r"\1" + PLACEHOLDER),
    (re.compile(r"(?im)(\b(?:read-only|read-write)-community\s+)\S+"), r"\1" + PLACEHOLDER),
    # AAA shared keys
    (re.compile(r"(?im)(\b(?:tacacs|radius)(?:-server)?\s+(?:host\s+\S+\s+)?key\s+(?:\d\s+)?)\S+"),
     r"\1" + PLACEHOLDER),
    (re.compile(r"(?im)^([ \t]*key[ \t]+(?:\d[ \t]+)?)\S+$"), r"\1" + PLACEHOLDER),
    # IPsec / IKE pre-shared keys
    (re.compile(r"(?im)(\bpre-shared-key\s+(?:local\s+|remote\s+)?(?:\d\s+)?)\S+"), r"\1" + PLACEHOLDER),
    (re.compile(r"(?im)(\bcrypto\s+isakmp\s+key\s+(?:\d\s+)?)\S+"), r"\1" + PLACEHOLDER),
    # Juniper / Fortinet / PAN style: encrypted-password "...", set password ENC xxx, psksecret ENC xxx
    (re.compile(r'(?im)(\bencrypted-password\s+)"?[^"\s;]+"?'), r"\1" + PLACEHOLDER),
    (re.compile(r'(?im)(\b(?:authentication-key|pre-shared-key|ike-pre-shared-key)\s+)"[^"]+"'),
     r"\1" + PLACEHOLDER),
    (re.compile(r"(?im)(\bset\s+(?:password|psksecret|passwd|secret)\s+(?:ENC\s+)?)\S+"), r"\1" + PLACEHOLDER),
    # XML-ish (PAN-OS): <phash>...</phash>, <password>...</password>, <key>...</key>
    (re.compile(r"(?is)(<(?:phash|password|key|secret|psk)>)[^<]+(</)"), r"\1" + PLACEHOLDER + r"\2"),
    # PEM private key blocks
    # body = anything except the next "-----" marker (so the scan stops there), capped at 16 KiB; an unterminated block is
    # still blanked up to that cap instead of being left in clear text
    (re.compile(r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----(?:[^-]|-(?!----)){0,16384}(?:-----END [A-Z ]{0,40}PRIVATE KEY-----)?"),
     "-----BEGIN PRIVATE KEY-----" + PLACEHOLDER + "-----END PRIVATE KEY-----"),
]


def redact_secrets(text: str) -> str:
    """Return ``text`` with secret values replaced by ``<REDACTED>``."""
    if not text:
        return text
    out = text
    for rx, repl in _RULES:
        out = rx.sub(repl, out)
    return out


def redact_line(line: str) -> str:
    return redact_secrets(line) if isinstance(line, str) else line


def contains_secret(text: str) -> bool:
    return bool(text) and redact_secrets(text) != text
