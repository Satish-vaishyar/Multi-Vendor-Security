"""Secret detection and redaction for uploaded configuration (RTM S07; CM-062, CM-063, CM-076, CM-109).

Runs BEFORE any parser. Findings never contain the secret: only a rule id, location, a masked preview and a salted
fingerprint (HMAC with a per-scan salt, so a fingerprint cannot be brute-forced offline or correlated across scans).
`redact()` returns text that is safe to log, store or send to an approved LLM path.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import re
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple

REDACTED = "[REDACTED]"


@dataclass(frozen=True)
class SecretFinding:
    rule_id: str
    kind: str
    path: str
    line: int
    preview: str          # masked, e.g. "AK***(20)"
    fingerprint: str      # HMAC(salt, value)[:12]


# (rule_id, kind, regex, group holding the secret value)
_RULES: List[Tuple[str, str, "re.Pattern[str]", int]] = [
    ("SEC-PEM", "private key", re.compile(
        r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----.*?-----END (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----",
        re.S), 0),
    ("SEC-AWS-KEY-ID", "AWS access key id", re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16})\b"), 1),
    ("SEC-AWS-SECRET", "AWS secret access key", re.compile(
        r"""(?i)aws_?secret_?access_?key["']?\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})\b"""), 1),
    ("SEC-AZURE-STORAGE", "Azure storage account key", re.compile(r"AccountKey=([A-Za-z0-9+/=]{40,})"), 1),
    ("SEC-GCP-KEY-ID", "GCP service-account key id", re.compile(r'"private_key_id"\s*:\s*"([0-9a-f]{40})"'), 1),
    ("SEC-GITHUB", "GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"), 1),
    ("SEC-SLACK", "Slack token", re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})"), 1),
    ("SEC-JWT", "JSON web token", re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"), 1),
    ("SEC-DO", "DigitalOcean token", re.compile(r"\b(dop_v1_[a-f0-9]{64})\b"), 1),
    ("SEC-ALIBABA", "Alibaba access key", re.compile(r"\b(LTAI[A-Za-z0-9]{12,20})\b"), 1),
    ("SEC-TENCENT", "Tencent secret id", re.compile(r"\b(AKID[A-Za-z0-9]{32})\b"), 1),
    ("SEC-URL-CRED", "credential in URL", re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@\"']+:([^\s/@\"']{3,})@"), 1),
    ("SEC-GENERIC", "hard-coded credential", re.compile(
        r"""(?ix)\b[\w.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)[\w.-]*
            ["']?\s*[:=]\s*(?:"([^"\s]{8,})"|'([^'\s]{8,})'|([^\s"'#,{}\[\]]{12,}))"""), -1),
]

_PLACEHOLDER_PARTS = ("example", "changeme", "change_me", "replace", "placeholder", "your_", "your-", "<", ">", "${",
                      "{{", "xxxx", "****", "redacted", "dummy", "sample", "todo", "fixme")
_REFERENCE_PREFIXES = ("var.", "local.", "data.", "module.", "each.", "aws_", "azurerm_", "google_", "!", "$", "(",
                       "arn:", "projects/", "/subscriptions/", "https://", "http://", "ref(", "secretref")


def _entropy(value: str) -> float:
    counts = {c: value.count(c) for c in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def _is_placeholder(value: str, generic: bool) -> bool:
    low = value.lower()
    if any(p in low for p in _PLACEHOLDER_PARTS):
        return True
    if generic:
        # references to other config, short/low-entropy words and plain identifiers are not credentials
        return low.startswith(_REFERENCE_PREFIXES) or _entropy(value) < 3.0 or re.fullmatch(r"[a-z_.-]+", low) is not None
    return False


def _spans(text: str) -> Iterator[Tuple[str, str, int, int, str]]:
    """Yield (rule_id, kind, start, end, value) for non-overlapping, non-placeholder matches."""
    taken: List[Tuple[int, int]] = []
    for rule_id, kind, rx, group in _RULES:
        for m in rx.finditer(text):
            idx = group
            if group == -1:
                idx = next(i for i in (1, 2, 3) if m.group(i) is not None)
            start, end, value = m.start(idx), m.end(idx), m.group(idx)
            if _is_placeholder(value, generic=(rule_id == "SEC-GENERIC")):
                continue
            if any(start < b and end > a for a, b in taken):
                continue
            taken.append((start, end))
            yield rule_id, kind, start, end, value


def _mask(value: str) -> str:
    return f"{value[:2]}***({len(value)})"


def scan_text(path: str, text: str, salt: bytes) -> List[SecretFinding]:
    out = []
    for rule_id, kind, start, _end, value in sorted(_spans(text), key=lambda s: s[2]):
        fp = hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
        out.append(SecretFinding(rule_id, kind, path, text.count("\n", 0, start) + 1, _mask(value), fp))
    return out


def redact(text: str) -> str:
    """Replace every detected secret value with [REDACTED]; everything else is preserved byte for byte."""
    out, pos = [], 0
    for _r, _k, start, end, _v in sorted(_spans(text), key=lambda s: s[2]):
        out.append(text[pos:start])
        out.append(REDACTED)
        pos = end
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
