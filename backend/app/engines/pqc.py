"""Engine 2 — PQC Readiness (arch.md §16-18). Deterministic, no ML.

Reads crypto-relevant canonical properties + software inventory, builds a
CBOM (asset/protocol/algorithm/key/class/pqc-status/migration) and a 0-100
readiness score. Separate from compliance scoring by design.
"""
from __future__ import annotations
from typing import Any, Dict, List

WEAK = {"DES", "3DES", "RC4", "MD5", "SHA1", "SHA-1", "DSA1024", "DH-GROUP1", "RSA1024"}
QUANTUM_VULNERABLE = {"RSA", "ECDSA", "DSA", "DH", "ECDH"}
QUANTUM_SAFE = {"AES-256", "AES-128", "SHA-256", "SHA-384", "SHA-512", "ML-KEM", "ML-DSA", "SLH-DSA"}


def _flat_get(flat: Dict[str, Any], *names: str) -> Any:
    for n in names:
        if n in flat:
            return flat[n]
    return None


def build_cbom(asset_id: str, flat_ir: Dict[str, Any], components: List[Dict]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    weak = bool(_flat_get(flat_ir, "CRYPTO.WEAK_ALGO"))
    tls = _flat_get(flat_ir, "CRYPTO.TLS_MIN")
    rsa = _flat_get(flat_ir, "CRYPTO.RSA_KEY_SIZE")
    ike = _flat_get(flat_ir, "CRYPTO.IKE_VERSION")
    sshv = _flat_get(flat_ir, "SSH.VERSION")
    if weak:
        rows.append({"asset_id": asset_id, "protocol": "services", "algorithm": "WEAK-ALGO (DES/3DES/RC4/MD5/SHA1/DH-g1)",
                     "key_size": None, "usage": "management crypto", "location": "config",
                     "klass": "classical", "pqc_status": "MIGRATION_REQUIRED",
                     "migration": "Replace with AES-256 / SHA-256+ / DH-group14+ / TLS 1.2+"})
    if rsa is not None:
        try:
            bits = int(rsa)
        except Exception:
            bits = 0
        rows.append({"asset_id": asset_id, "protocol": "SSH/IKE", "algorithm": "RSA",
                     "key_size": bits, "usage": "host key", "location": "config",
                     "klass": "classical",
                     "pqc_status": "MIGRATION_REQUIRED" if bits < 2048 else "TRANSITION",
                     "migration": "Plan ML-DSA / hybrid migration; keep >=2048-bit RSA until then" if bits >= 2048 else "Regenerate >=2048-bit RSA now; plan PQC migration"})
    if tls is not None:
        rows.append({"asset_id": asset_id, "protocol": "TLS/HTTPS", "algorithm": f"TLS>={tls}",
                     "key_size": None, "usage": "management plane", "location": "config",
                     "klass": "classical", "pqc_status": "READY" if str(tls) >= "1.2" else "MIGRATION_REQUIRED",
                     "migration": "" if str(tls) >= "1.2" else "Enforce TLS >= 1.2"})
    if ike is not None:
        rows.append({"asset_id": asset_id, "protocol": "IPsec/IKE", "algorithm": f"IKEv{ike}",
                     "key_size": None, "usage": "site crypto", "location": "config",
                     "klass": "classical", "pqc_status": "TRANSITION" if str(ike) == "2" else "MIGRATION_REQUIRED",
                     "migration": "" if str(ike) == "2" else "Migrate IKEv1 -> IKEv2"})
    ssh_algo_weak = sshv == 1
    if ssh_algo_weak:
        rows.append({"asset_id": asset_id, "protocol": "SSH", "algorithm": "SSHv1",
                     "key_size": None, "usage": "remote admin", "location": "config",
                     "klass": "deprecated", "pqc_status": "MIGRATION_REQUIRED",
                     "migration": "Enforce SSH version 2"})
    for c in components:
        prod = f"{c.get('vendor','')}/{c.get('product','')}".lower()
        if any(k in prod for k in ("openssl", "openssh", "tls", "ipsec")):
            rows.append({"asset_id": asset_id, "protocol": c.get("product", ""), "algorithm": c.get("product", ""),
                         "key_size": None, "usage": c.get("component_type", ""), "location": "inventory",
                         "klass": "classical", "pqc_status": "TRANSITION",
                         "migration": "Track vendor PQC/hybrid roadmap", "version": c.get("version", "")})
    if not rows:
        rows.append({"asset_id": asset_id, "protocol": "—", "algorithm": "no crypto signals in config",
                     "key_size": None, "usage": "", "location": "",
                     "klass": "unknown", "pqc_status": "UNKNOWN", "migration": "Add crypto inventory"})
    return rows


def readiness(cbom: List[Dict[str, Any]]) -> Dict[str, Any]:
    score, n = 0, 0
    counts = {"READY": 0, "TRANSITION": 0, "MIGRATION_REQUIRED": 0, "UNKNOWN": 0}
    weight = {"READY": 100, "TRANSITION": 60, "MIGRATION_REQUIRED": 10, "UNKNOWN": 40, "classical": 55,
              "pqc-ready": 100, "hybrid": 80, "deprecated": 5, "unknown": 40}
    for r in cbom:
        st = r.get("pqc_status", "UNKNOWN")
        counts[st] = counts.get(st, 0) + 1
        score += weight.get(st, 40)
        n += 1
    return {"readiness_score": round(score / n, 1) if n else 0.0, "counts": counts,
            "algorithms": cbom,
            "migration_recommendations": [r["migration"] for r in cbom if r.get("migration")]}
