"""Vendor version normalizer (cve_okf §9): raw → comparable token tuple.

Handles: 1.2.3, 10.4, 17.9.4a, 17.9.4a-ES, v7.2.1, R81.10, 22.4R3, 6.4.15, 7.2(1).
Strategy: lowercase, strip leading v/r, split trailing train tags (-ES/-S),
tokenize numeric runs vs letter suffixes, compare numerically then lexically.
"""
from __future__ import annotations
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class NormVersion:
    nums: tuple
    suffix: str = ""
    train: str = ""

    def __lt__(self, o: "NormVersion") -> bool:
        if self.nums != o.nums:
            return self.nums < o.nums
        if (self.suffix == "") != (o.suffix == ""):
            return self.suffix != ""  # bare release > suffixed pre-release
        if self.suffix != o.suffix:
            return self.suffix < o.suffix
        return self.train < o.train

    def __eq__(self, o: object) -> bool:
        return isinstance(o, NormVersion) and (self.nums, self.suffix, self.train) == (o.nums, o.suffix, o.train)

    def __le__(self, o: "NormVersion") -> bool:
        return self == o or self < o


def normalize(raw: str) -> NormVersion:
    s = (raw or "").strip().lower()
    s = re.sub(r"\\(.)", r"\1", s)               # NVD CPE escapes: 12.0\(32\)S12
    s = re.sub(r"^[vr](?=\d)", "", s)          # v7.2.1, r81.10
    train = ""
    m = re.search(r"[-+](es|s|p\d*|x|t)$", s)
    if m:
        train = m.group(1)
        s = s[:m.start()]
    # Junos style 22.4r3 -> 22.4.3 ; 7.2(1) -> 7.2.1 ; r81.10 -> 81.10
    s = re.sub(r"(\d)[r](\d)", r"\1.\2", s)
    s = re.sub(r"[()]", ".", s)
    parts = [p for p in re.split(r"[.\-_ ]+", s) if p != ""]
    nums: list = []
    suffix = ""
    for p in parts:
        m2 = re.match(r"(\d+)([a-z]+.*)?$", p)
        if m2:
            nums.append(int(m2.group(1)))
            if m2.group(2):
                suffix = m2.group(2)
        elif p:
            suffix = (suffix + p) if not suffix else suffix
    # checkpoint R81.10 -> (81,10)
    return NormVersion(nums=tuple(nums), suffix=suffix, train=train)


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
