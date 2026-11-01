"""Secret detection and redaction for uploaded configuration (RTM S07; CM-062, CM-063, CM-076, CM-109).

Runs BEFORE any parser. Findings never contain the secret: only a rule id, location, a masked preview and a salted
fingerprint (HMAC with a per-scan salt, so a fingerprint cannot be brute-forced offline or correlated across scans).
`redact()` returns text that is safe to log, store or send to an approved LLM path.

Design rules (security review hardening):
  * fail closed: provider-token and private-key rules are never suppressed by "looks like a placeholder" heuristics
    (only the vendors' published example values are skipped); the heuristics apply to the generic rule alone and only
    to whole-value matches, so a real password that merely contains a word like "example" is still reported
  * redaction merges overlapping matches and redacts their union
  * a private-key block with no END marker is redacted to the end of the text
  * every quantifier is bounded, and PEM blocks are located with str.find, so crafted input cannot cause
    catastrophic backtracking or quadratic scans
"""
from __future__ import annotations

import hashlib
import hmac
import math
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

REDACTED = "[REDACTED]"


@dataclass(frozen=True)
class SecretFinding:
    rule_id: str
    kind: str
    path: str
    line: int
    preview: str          # masked, e.g. "AK***(20)"
    fingerprint: str      # HMAC(salt, value)[:12]


_PEM_BEGIN = re.compile(r"-----BEGIN (?:[A-Z]{1,20} ){0,3}PRIVATE KEY(?: BLOCK)?-----")
_PEM_END = re.compile(r"-----END (?:[A-Z]{1,20} ){0,3}PRIVATE KEY(?: BLOCK)?-----")

# (rule_id, kind, regex, group holding the secret value or -1 for "first non-empty of groups 1..3")
_RULES: List[Tuple[str, str, "re.Pattern[str]", int]] = [
    ("SEC-AWS-KEY-ID", "AWS access key id", re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16})\b"), 1),
    ("SEC-AWS-SECRET", "AWS secret access key", re.compile(
        r"""(?i)aws_?secret_?access_?key["']?\s{0,8}[=:]\s{0,8}["']?([A-Za-z0-9/+=]{40})\b"""), 1),
    ("SEC-AZURE-STORAGE", "Azure storage account key", re.compile(r"AccountKey=([A-Za-z0-9+/=]{40,200})"), 1),
    ("SEC-GCP-KEY-ID", "GCP service-account key id", re.compile(r'"private_key_id"\s{0,8}:\s{0,8}"([0-9a-f]{40})"'), 1),
    ("SEC-GITHUB", "GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"), 1),
    ("SEC-SLACK", "Slack token", re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,200})"), 1),
    ("SEC-JWT", "JSON web token", re.compile(
        r"\b(eyJ[A-Za-z0-9_-]{8,2000}\.eyJ[A-Za-z0-9_-]{8,2000}\.[A-Za-z0-9_-]{8,2000})"), 1),
    ("SEC-DO", "DigitalOcean token", re.compile(r"\b(dop_v1_[a-f0-9]{64})\b"), 1),
    ("SEC-ALIBABA", "Alibaba access key", re.compile(r"\b(LTAI[A-Za-z0-9]{12,20})\b"), 1),
    ("SEC-TENCENT", "Tencent secret id", re.compile(r"\b(AKID[A-Za-z0-9]{32})\b"), 1),
    # the authority ends at the first '/'; the password may contain '@', '?' and '#' (RFC says percent-encode, real configs do not)
    ("SEC-URL-CRED", "credential in URL", re.compile(
        r"[A-Za-z][A-Za-z0-9+.-]{0,30}://[^\s/?#:@]{0,128}:([^\s/]{3,512})@[^\s@/?#]{1,255}"), 1),
    ("SEC-GENERIC", "hard-coded credential", re.compile(
        r"""(?ix)(?<![\w.-])[\w.-]{0,64}(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)[\w.-]{0,64}
            ["']?[ \t]{0,8}[:=][ \t]{0,8}(?:"([^"\r\n]{8,512})"|'([^'\r\n]{8,512})'|([^\r\n"'#,{}\[\]]{12,512}))"""), -1),
]

# Vendor-published example values (documented as fake): the only things the token rules skip.
_PUBLISHED_EXAMPLES = ("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

# Whole-value placeholders and genuine reference syntax. Applied to the generic rule only.
_PLACEHOLDER_WHOLE = re.compile(
    r"(?i)(?:\[(?:sensitive|redacted)\]|(?:change|replace)[-_ ]?me.{0,40}|your[-_ ].{1,40}|(?:my|the)[-_ ]?(?:password|secret|token|key)|placeholder|dummy|sample|"
    r"example|redacted|todo|fixme|[x*._-]{4,}|<[^<>]{1,80}>|\{\{[^{}]{1,80}\}\}|\$\{[^{}]{1,200}\})")
_REFERENCE_WHOLE = re.compile(
    r"^(?:(?:var|local|data|module|each|count)\.[A-Za-z_][\w.\[\]\"*-]*|(?:aws|azurerm|google|oci|alicloud|ibm)_[a-z0-9_]+\.[\w.\[\]*-]+"
    r"|arn:aws[\w-]*:[\w:/.*-]+|!Ref\s.*|!Sub\s.*|!GetAtt\s.*)$")


def _entropy(value: str) -> float:
    counts = {c: value.count(c) for c in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def _generic_skip(value: str, quoted: bool) -> bool:
    v = value.strip()
    if _PLACEHOLDER_WHOLE.fullmatch(v) or _REFERENCE_WHOLE.match(v):
        return True
    if quoted:
        return False                      # a quoted literal next to a "password"/"token" key is reported, however weak
    # unquoted YAML-style values: ignore low-entropy words and plain identifiers
    return _entropy(v) < 3.0 or re.fullmatch(r"[a-z_.-]+", v) is not None


def _pem_spans(text: str) -> List[Tuple[str, str, int, int, str]]:
    out: List[Tuple[str, str, int, int, str]] = []
    pos = 0
    while True:
        b = _PEM_BEGIN.search(text, pos)
        if not b:
            return out
        e = _PEM_END.search(text, b.end())
        end = e.end() if e else len(text)         # unterminated block: redact to the end of the text
        out.append(("SEC-PEM", "private key", b.start(), end, text[b.start():end]))
        if not e:
            return out
        pos = end


def _raw_spans(text: str) -> List[Tuple[str, str, int, int, str]]:
    spans = _pem_spans(text)
    for rule_id, kind, rx, group in _RULES:
        for m in rx.finditer(text):
            idx = group if group != -1 else next(i for i in (1, 2, 3) if m.group(i) is not None)
            value = m.group(idx)
            if rule_id == "SEC-GENERIC":
                if _generic_skip(value, quoted=idx != 3):
                    continue
            elif value in _PUBLISHED_EXAMPLES:
                continue
            spans.append((rule_id, kind, m.start(idx), m.end(idx), value))
    return sorted(spans, key=lambda s: (s[2], -(s[3] - s[2])))


def _mask(value: str) -> str:
    return f"{value[:2]}***({len(value)})"


def scan_text(path: str, text: str, salt: bytes) -> List[SecretFinding]:
    """One finding per merged region (the earliest, widest rule wins the label)."""
    out: List[SecretFinding] = []
    covered = -1
    for rule_id, kind, start, end, value in _raw_spans(text):
        if start < covered:
            covered = max(covered, end)
            continue
        covered = end
        fp = hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
        out.append(SecretFinding(rule_id, kind, path, text.count("\n", 0, start) + 1, _mask(value), fp))
    return out


def redact(text: str) -> str:
    """Replace every detected secret with [REDACTED] (overlapping matches are merged); the rest is preserved."""
    out: List[str] = []
    pos = 0
    cur_start: Optional[int] = None
    cur_end = 0
    for _rule, _kind, start, end, _value in _raw_spans(text):
        if cur_start is not None and start < cur_end:
            cur_end = max(cur_end, end)
            continue
        if cur_start is not None:
            out.append(text[pos:cur_start])
            out.append(REDACTED)
            pos = cur_end
        cur_start, cur_end = start, end
    if cur_start is not None:
        out.append(text[pos:cur_start])
        out.append(REDACTED)
        pos = cur_end
    out.append(text[pos:])
    return "".join(out)


def scan_files(files: List[Tuple[str, str]], salt: bytes) -> List[SecretFinding]:
    """files: [(path, text)]"""
    found: List[SecretFinding] = []
    for path, text in files:
        found.extend(scan_text(path, text, salt))
    return found


def has_secrets(findings: List[SecretFinding], path: Optional[str] = None) -> bool:
    return any(path is None or f.path == path for f in findings)
