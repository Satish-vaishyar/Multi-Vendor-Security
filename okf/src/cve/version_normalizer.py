"""Vendor version normalizer (cve_okf §9): raw -> comparable value.

Formats handled (all verified against realistic advisories in tests/test_cve_versions.py):
  1.2.3 | 10.4 | v7.2.1 | R81.10                       generic dotted
  17.9.4a  16.12.4  9.3(5)  10.3(4a)  15.2(4)M7        Cisco IOS / IOS-XE / NX-OS (letter = rebuild AFTER the base)
  20.4R3  20.4R3-S2  20.4R3-S2.1  12.3X48-D30          Juniper Junos (S = service release AFTER R, D = maintenance)
  10.2.3  10.2.3-h4                                    Palo Alto PAN-OS (hX = hotfix AFTER the base)
  4.28.3M  4.28.3.1F                                   Arista EOS (trailing letter = train, ordered after the bare number)
  7.2.10                                               FortiOS (numeric compare, 10 > 6)

Ordering rule:   numbers  <  pre-release (rc/beta/alpha/dev/eft)  <  bare release  <  post-release markers
Post-release markers are compared naturally (m9 < m10, S2 < S4, S2 < S2.1). Trailing zero components are
insignificant (7.2 == 7.2.0), which matters for inclusive range ends.
"""
from __future__ import annotations
import re
from dataclasses import dataclass

_PRE = re.compile(r"^(rc|beta|alpha|pre|dev|eft|preview|snapshot)\d*$")


def _natural(text: str) -> tuple:
    """'m10' -> ((0,'m'),(1,10)): numbers compare numerically, letters lexically, never mixed-type."""
    return tuple((1, int(t)) if t.isdigit() else (0, t) for t in re.findall(r"\d+|[a-z]+", text.lower()))


def _strip_zeros(nums: tuple) -> tuple:
    n = list(nums)
    while n and n[-1] == 0:
        n.pop()
    return tuple(n)


@dataclass(frozen=True)
class NormVersion:
    nums: tuple
    suffix: str = ""
    train: str = ""
    pre: bool = False          # rc / beta / alpha ... : sorts BEFORE the bare release

    # -- ordering ---------------------------------------------------------------
    def _key(self) -> tuple:
        rank = -1 if self.pre else (1 if self.suffix else 0)
        return (_strip_zeros(self.nums), rank, _natural(self.suffix), self.train)

    def __lt__(self, o: "NormVersion") -> bool:
        return self._key() < o._key()

    def __eq__(self, o: object) -> bool:
        return isinstance(o, NormVersion) and self._key() == o._key()

    def __hash__(self) -> int:
        return hash(self._key())

    def __le__(self, o: "NormVersion") -> bool:
        return self == o or self < o


def normalize(raw: str) -> NormVersion:
    s = (raw or "").strip().lower()
    s = re.sub(r"\\(.)", r"\1", s)                    # NVD CPE escapes: 12.0\(32\)S12
    s = s.replace(":", "")                             # CPE version:update glue, e.g. junos 20.4:r3-s2
    s = re.sub(r"^[vr](?=\d)", "", s)                  # v7.2.1, r81.10
    train = ""
    m = re.search(r"[-+](es|s|p\d*|x|t)$", s)         # trailing train tags (IOS -ES / -S)
    if m:
        train = m.group(1)
        s = s[:m.start()]
    # Junos 22.4r3 / 12.3x48 -> 22.4.3 / 12.3.48 ; 7.2(1) -> 7.2.1
    s = re.sub(r"(\d)[rx](\d)", r"\1.\2", s)
    s = re.sub(r"[()]", ".", s)
    parts = [p for p in re.split(r"[.\-_ ]+", s) if p != ""]
    nums: list = []
    post: list = []
    pre = False
    seen_marker = False
    for p in parts:
        m2 = re.match(r"(\d+)([a-z]+.*)?$", p)
        if m2 and not seen_marker:
            nums.append(int(m2.group(1)))
            if m2.group(2):                            # 4a, 4m7, 3x48: numeric core then a marker
                tail = m2.group(2)
                if _PRE.match(tail):
                    pre = True
                else:
                    post.append(tail)
                seen_marker = True
        elif m2 and seen_marker:                       # numbers AFTER a marker belong to the marker: S2.1, h4
            post.append(p)
        elif _PRE.match(p):
            pre = True
            seen_marker = True
        elif p:
            post.append(p)
            seen_marker = True
    suffix = "".join(post) if not post or not nums else ".".join(post) if len(post) > 1 else post[0]
    if not nums and post:                              # opaque token (e.g. "blah-blah"): keep the first one
        suffix = post[0]
    return NormVersion(nums=tuple(nums), suffix=suffix, train=train, pre=pre)


def compare(a: str, op: str, b: str) -> bool:
    na, nb = normalize(a), normalize(b)
    if op in ("=", "==", "EQ"):
        return na == nb
    if op in ("!=", "NE"):
        return na != nb
    if op in (">=", "GE"):
        return na == nb or nb < na
    if op in ("<=", "LE"):
        return na == nb or na < nb
    if op in (">", "GT"):
        return nb < na
    if op in ("<", "LT"):
        return na < nb
    raise ValueError(f"unknown op {op}")
