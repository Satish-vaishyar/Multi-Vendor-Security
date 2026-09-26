"""CBOM builder (cve_okf §12): software components + crypto IR props → CBOM rows.

Shared component inventory feeds both CVE correlation and crypto analysis.
Classification: classical / pqc-ready / hybrid / deprecated / unknown.
"""
from __future__ import annotations
from typing import Any, Dict, List

WEAK = {"des", "3des", "rc4", "md5", "sha1", "dh-group1", "ikev1", "tls1.0", "tls1.1", "sslv3"}
PQC_READY = {"aes-256", "sha-512", "ecdsa-p384", "ed25519", "ml-kem", "ml-dsa", "slh-dsa"}
HYBRID = {"hybrid-kem", "x25519-kyber", "ecdhe-kyber"}


def classify(algo: str) -> str:
    a = (algo or "").lower()
    if a in PQC_READY:
        return "pqc-ready"
    if a in HYBRID:
        return "hybrid"
    if a in WEAK:
        return "deprecated"
    if not a:
        return "unknown"
    return "classical"


def build_cbom(asset_id: str, components: List[Dict[str, Any]],
               crypto_props: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for c in components:
        name = f"{c.get('vendor')}/{c.get('product')} {c.get('version', '')}".strip()
        rows.append({"asset_id": asset_id, "protocol": c.get("component_type", ""),
                     "algorithm": name, "key_size": None, "usage": "software",
                     "location": "device", "klass": "classical", "pqc_status": "unknown"})
    for k, v in (crypto_props or {}).items():
        if "WEAK" in k and v is True:
            rows.append({"asset_id": asset_id, "protocol": "management",
                         "algorithm": "weak-algo-present", "key_size": None,
                         "usage": "config", "location": "canonical-ir",
                         "klass": "deprecated", "pqc_status": "migration-required"})
    return rows
