"""CPE Resolver (cve_okf §6): vendor/product → CPE 2.3 strings + aliases.

Deterministic alias table (curated) + normalization. No ML here.
"""
from __future__ import annotations
from typing import Dict, List

# (vendor_alias, product_alias) -> canonical (vendor, product, part)
ALIASES: Dict[tuple, tuple] = {
    ("cisco", "ios-xe"): ("cisco", "ios_xe", "o"),
    ("cisco", "ios"): ("cisco", "ios", "o"),
    ("cisco", "nx-os"): ("cisco", "nx-os", "o"),
    ("cisco", "asa"): ("cisco", "adaptive_security_appliance_software", "o"),
    ("cisco", "ftd"): ("cisco", "firepower_threat_defense", "a"),
    ("juniper", "junos"): ("juniper", "junos", "o"),
    ("juniper", "junos-os"): ("juniper", "junos", "o"),
    ("fortinet", "fortios"): ("fortinet", "fortios", "o"),
    ("fortinet", "fortigate"): ("fortinet", "fortios", "o"),
    ("paloalto", "pan-os"): ("paloaltonetworks", "pan-os", "o"),
    ("paloaltonetworks", "pan-os"): ("paloaltonetworks", "pan-os", "o"),
    ("arista", "eos"): ("arista", "eos", "o"),
    ("openbsd", "openssh"): ("openbsd", "openssh", "a"),
    ("openssl", "openssl"): ("openssl", "openssl", "a"),
}


def _norm(s: str) -> str:
    return (s or "").strip().lower().replace(" ", "_")


def canonical(vendor: str, product: str) -> tuple:
    """Alias-aware canonical (vendor, product) for KB lookups."""
    v, p = _norm(vendor), _norm(product)
    cv, cp, _ = ALIASES.get((v, p), (v, p, "o"))
    return cv, cp


def resolve(vendor: str, product: str, version: str = "*") -> List[str]:
    v, p = _norm(vendor), _norm(product)
    canon = ALIASES.get((v, p), (v or "*", p or "*", "o"))
    cv, cp, part = canon
    cpe = f"cpe:2.3:{part}:{cv}:{cp}:{version if version not in ('', None) else '*'}:*:*:*:*:*:*:*"
    out = [cpe]
    if v != cv or p != cp:  # also emit literal form
        out.append(f"cpe:2.3:{part}:{v}:{p}:{version}:*:*:*:*:*:*:*")
    return out


def confidence(vendor: str, product: str, version: str) -> Dict[str, float]:
    v, p = _norm(vendor), _norm(product)
    known = (v, p) in ALIASES
    return {"cpe_confidence": 0.99 if known else 0.55,
            "version_confidence": 0.98 if version else 0.30}
