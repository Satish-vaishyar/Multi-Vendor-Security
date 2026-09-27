"""Engine 2 — PQC Readiness (arch.md §16-18). Deterministic, no ML.

Reads crypto-relevant canonical properties + software inventory, builds a
CBOM (asset/protocol/algorithm/key/class/pqc-status/migration) and a 0-100
readiness score. Separate from compliance scoring by design.

The row shape is a simplified projection of an OWASP CycloneDX CBOM
cryptographic-asset (ECMA-424, spec 1.6): algorithm ~ name, key_size ~
related material size, function ~ cryptoFunctions, pqc_status ~ our
quantum-safety assessment. It is not a full CycloneDX document — just the
fields a network-config audit can actually observe.

Real-world semantics (verified Sep 2026):
- NIST FIPS 203 (ML-KEM, key exchange), FIPS 204 (ML-DSA, signatures),
  FIPS 205 (SLH-DSA, hash-based backup signatures) finalized Aug 2024 —
  deploy now. HQC (backup KEM) selected Mar 2025, standard in progress.
  FN-DSA/FALCON (FIPS 206) still draft, expected late 2026 / early 2027.
- NIST IR 8547 timeline: deprecate quantum-vulnerable public-key
  algorithms after 2030, disallow after 2035. NSA CNSA 2.0 migration
  began 2025. "Plan migration" below means: hybrid now, fully quantum-safe
  before those dates, externally-exposed systems first.
- MIGRATION_REQUIRED: broken today AND quantum-broken — DES/3DES/RC4/MD5/
  SHA-1, RSA < 2048, DH group1, SSHv1, TLS < 1.2, IKEv1. Fix now (P1).
- TRANSITION: currently-secure classical that is quantum-vulnerable —
  RSA >= 2048, TLS 1.2/1.3 with classical key exchange, IKEv2 with
  classical DH, SSHv2 with classical KEX, classical crypto libs.
  Plan hybrid migration: ML-KEM hybrids for key exchange (available now),
  ML-DSA for signatures when the product supports it (P2).
  NOTE: TLS 1.2 is *not* quantum-safe — it only fixes classical attacks —
  so it is TRANSITION, never READY.
- SSH specifics (openssh.com/pq.html): hybrid KEX is the available,
  default-on migration — sntrup761x25519-sha512 since OpenSSH 9.0
  (RFC 9941), mlkem768x25519-sha256 since 9.9, default since 10.0
  (RFC 10042); 10.1 warns on non-PQ KEX. Post-quantum *signatures*
  (ML-DSA host keys) are NOT in stable OpenSSH yet — so for SSH host
  keys the honest remedy is hybrid KEX now + keep RSA >= 3072, and
  migrate signatures when OpenSSH ships PQ-sig support.
- READY: explicit PQC / hybrid algorithm present (ML-KEM, ML-DSA,
  SLH-DSA, HQC, FN-DSA/Falcon, or "hybrid"/"pqc" in the inventory).
- UNKNOWN: no crypto signals found in the config.
- Symmetric ciphers / hashes with sufficient strength (AES-128/256,
  SHA-256/384/512) are Grover-resilient and not flagged per-row by this
  engine; they are covered in the page footnote.
"""
from __future__ import annotations
from typing import Any, Dict, List

WEAK = {"DES", "3DES", "RC4", "MD5", "SHA1", "SHA-1", "DSA1024", "DH-GROUP1", "RSA1024"}
QUANTUM_VULNERABLE = {"RSA", "ECDSA", "DSA", "DH", "ECDH"}
QUANTUM_SAFE = {"AES-256", "AES-128", "SHA-256", "SHA-384", "SHA-512", "ML-KEM", "ML-DSA", "SLH-DSA",
                "HQC", "FN-DSA"}
# Substrings that mark an inventory component as explicitly post-quantum / hybrid.
# (Matched only against openssl/openssh/tls/ipsec inventory entries, so names
# like CrowdStrike "Falcon" elsewhere can never false-positive here.)
PQC_MARKERS = ("ml-kem", "mlkem", "ml-dsa", "mldsa", "slh-dsa", "fn-dsa", "falcon",
               "hqc", "kyber", "dilithium", "sphincs",
               "hybrid", "pqc", "quantum-safe", "quantum safe")


def _flat_get(flat: Dict[str, Any], *names: str) -> Any:
    for n in names:
        if n in flat:
            return flat[n]
    return None


def _tls_num(v: Any) -> float | None:
    """Parse '1.2', '1.10', 1.2, 'v1.3' -> float. Returns None if unparseable."""
    if v is None:
        return None
    try:
        s = str(v).strip().lower().lstrip("v")
        return float(s)
    except (TypeError, ValueError):
        return None


def _row(asset_id: str, *, protocol: str, algorithm: str, key_size: Any = None,
         version: str = "", usage: str = "", location: str = "",
         klass: str = "classical", pqc_status: str = "UNKNOWN",
         function: str = "", risk: str = "—", priority: str = "—", summary: str = "",
         migration: str = "", recommended: str = "",
         fix_steps: List[str] | None = None) -> Dict[str, Any]:
    """function ~ CycloneDX cryptoFunctions: key-exchange | signature |
    encryption | hashing | library (software whose internal primitives vary)."""
    return {"asset_id": asset_id, "protocol": protocol, "algorithm": algorithm,
            "key_size": key_size, "version": version, "usage": usage,
            "location": location, "klass": klass, "pqc_status": pqc_status,
            "function": function,
            "risk": risk, "priority": priority, "summary": summary,
            "migration": migration, "recommended": recommended or migration,
            "fix_steps": fix_steps or ([] if not migration else [migration])}


def build_cbom(asset_id: str, flat_ir: Dict[str, Any], components: List[Dict]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    weak = bool(_flat_get(flat_ir, "CRYPTO.WEAK_ALGO"))
    tls = _flat_get(flat_ir, "CRYPTO.TLS_MIN")
    rsa = _flat_get(flat_ir, "CRYPTO.RSA_KEY_SIZE")
    ike = _flat_get(flat_ir, "CRYPTO.IKE_VERSION")
    sshv = _flat_get(flat_ir, "SSH.VERSION")
    if weak:
        rows.append(_row(asset_id, protocol="Management crypto", algorithm="Weak algorithm (DES / 3DES / RC4 / MD5 / SHA-1 / DH group 1)",
                         usage="management-plane crypto", location="config",
                         klass="deprecated", pqc_status="MIGRATION_REQUIRED",
                         function="encryption",
                         risk="High — broken classically and by a quantum adversary",
                         priority="P1 — replace now",
                         summary="The config uses an algorithm that is already considered broken (e.g. DES, RC4, MD5, SHA-1, DH group 1). It must go regardless of quantum computers.",
                         migration="Replace with AES-256 / SHA-256+ / DH group 14+ / TLS 1.2+",
                         recommended="AES-256, SHA-256+, DH group 14+, TLS 1.2+ as interim; then hybrid PQC",
                         fix_steps=["Replace the weak primitive: AES-256 for encryption, SHA-256 or stronger for hashing, DH group 14+ for key exchange.",
                                    "Enforce TLS 1.2 minimum and SSH version 2 (see the TLS/SSH rows if present).",
                                    "Re-audit to confirm the weak-algorithm flag is gone, then schedule hybrid-PQC migration."]))
    if rsa is not None:
        try:
            bits = int(rsa)
        except Exception:
            bits = 0
        if bits < 2048:
            rows.append(_row(asset_id, protocol="SSH / IKE", algorithm="RSA",
                             key_size=bits, usage="host key", location="config",
                             klass="classical:quantum-vulnerable", pqc_status="MIGRATION_REQUIRED",
                             function="signature",
                             risk="High — factorable classically below 2048 bits; quantum-broken at any RSA size",
                             priority="P1 — regenerate now",
                             summary=f"An RSA key of {bits} bits was found (below the 2048-bit minimum). It is weak against classical attackers today and broken by a quantum attacker at any size.",
                             migration="Regenerate >= 2048-bit RSA now; plan PQC migration",
                             recommended="Regenerate RSA >= 3072 bits (CNSA 2.0) as interim; hybrid key exchange now; ML-DSA signatures when supported",
                             fix_steps=["Generate a new host key of at least 3072 bits (e.g. 'crypto key generate rsa modulus 3072').",
                                        "Deploy the new key and remove the old one, then re-audit.",
                                        "Enable hybrid post-quantum key exchange for the sessions using this key (see the SSH/TLS rows).",
                                        "Migrate signatures to ML-DSA (FIPS 204) once the product supports PQ signatures — deprecated after 2030, disallowed after 2035 (NIST IR 8547)."]))
        else:
            rows.append(_row(asset_id, protocol="SSH / IKE", algorithm="RSA",
                             key_size=bits, usage="host key", location="config",
                             klass="classical:quantum-vulnerable", pqc_status="TRANSITION",
                             function="signature",
                             risk="Medium — classically sound at this size, quantum-vulnerable (Shor)",
                             priority="P2 — plan migration",
                             summary=f"An RSA key of {bits} bits was found. It is fine against classical attackers but would be broken by a large quantum computer (Shor's algorithm). Signatures only need replacing before such computers exist; key exchange needs hybrid now (harvest-now-decrypt-later).",
                             migration="Keep >= 2048-bit RSA interim; hybrid key exchange now; plan ML-DSA signatures",
                             recommended="Hybrid key exchange now (ML-KEM hybrids); ML-DSA signatures (FIPS 204) when the product supports them",
                             fix_steps=["No emergency change — keep the current RSA key (>= 3072 bits preferred per CNSA 2.0).",
                                        "Enable hybrid post-quantum key exchange for sessions using this key — that is the part quantum attackers can exploit retroactively.",
                                        "Inventory every service using this key so you know the migration surface.",
                                        "Migrate signatures to ML-DSA when the product supports PQ signatures; finish before the NIST IR 8547 dates (deprecated after 2030, disallowed after 2035)."]))
    if tls is not None:
        num = _tls_num(tls)
        if num is not None and num < 1.2:
            rows.append(_row(asset_id, protocol="TLS / HTTPS", algorithm="TLS",
                             version=str(tls), usage="management plane", location="config",
                             klass="deprecated", pqc_status="MIGRATION_REQUIRED",
                             function="key-exchange",
                             risk="High — TLS < 1.2 is classically broken and quantum-vulnerable",
                             priority="P1 — enforce upgrade",
                             summary=f"TLS {tls} was found. Versions below 1.2 have known classical attacks, so this is broken today — not just a future quantum concern.",
                             migration="Enforce TLS >= 1.2 (1.3 preferred)",
                             recommended="TLS 1.3 preferred (1.2 minimum with strong suites) interim, then hybrid KEX with ML-KEM (FIPS 203)",
                             fix_steps=["Set the device minimum to TLS 1.2 or higher — 1.3 preferred (vendor syntax, e.g. 'ip http tls-version TLSv1.2') — and disable TLS 1.0/1.1.",
                                        "Restrict cipher suites to strong ones (ECDHE + AES-GCM), then re-audit.",
                                        "Plan hybrid key exchange (e.g. X25519MLKEM768) as the follow-up."]))
        else:
            rows.append(_row(asset_id, protocol="TLS / HTTPS", algorithm="TLS",
                             version=str(tls), usage="management plane (classical key exchange)", location="config",
                             klass="classical:quantum-vulnerable", pqc_status="TRANSITION",
                             function="key-exchange",
                             risk="Medium — TLS 1.2+ fixes classical attacks but key exchange is still quantum-vulnerable",
                             priority="P2 — plan migration",
                             summary=f"TLS {tls} was found. Classical attacks are addressed, but the key exchange is still RSA/ECDH-based, so a quantum attacker could decrypt recorded traffic later ('harvest now, decrypt later').",
                             migration="Classical KEX only — plan hybrid KEX with ML-KEM (FIPS 203)",
                             recommended="Hybrid key exchange (e.g. X25519MLKEM768); classical public-key deprecated after 2030, disallowed after 2035 (NIST IR 8547)",
                             fix_steps=["No emergency change — keep TLS 1.2+ with strong cipher suites (prefer TLS 1.3).",
                                        "When peers and the vendor support it, enable hybrid key exchange (e.g. X25519MLKEM768).",
                                        "Prioritize externally-exposed management interfaces first."]))
    if ike is not None:
        if str(ike) == "2":
            rows.append(_row(asset_id, protocol="IPsec / IKE", algorithm="IKEv2 (classical DH)",
                             version=str(ike), usage="site crypto", location="config",
                             klass="classical:quantum-vulnerable", pqc_status="TRANSITION",
                             function="key-exchange",
                             risk="Medium — IKEv2 with classical DH is quantum-vulnerable",
                             priority="P2 — plan migration",
                             summary="IKEv2 with classical Diffie-Hellman was found. It is the current correct choice, but the DH exchange is quantum-vulnerable.",
                             migration="Plan migration to IKEv2 with ML-KEM hybrid KEX; track vendor support",
                             recommended="IKEv2 + ML-KEM hybrid KEX when vendor supports it (classical deprecated after 2030 per NIST IR 8547)",
                             fix_steps=["No emergency change — stay on IKEv2 with DH group 14 or higher.",
                                        "When the vendor publishes ML-KEM hybrid-KEX support, enable it and re-audit."]))
        else:
            rows.append(_row(asset_id, protocol="IPsec / IKE", algorithm="IKEv1 (classical DH)",
                             version=str(ike), usage="site crypto", location="config",
                             klass="deprecated", pqc_status="MIGRATION_REQUIRED",
                             function="key-exchange",
                             risk="High — IKEv1 is deprecated and quantum-vulnerable",
                             priority="P1 — migrate now",
                             summary="IKEv1 was found. It is deprecated by vendors and must be migrated to IKEv2 regardless of quantum timelines.",
                             migration="Migrate IKEv1 -> IKEv2",
                             recommended="IKEv2 interim; then IKEv2 + ML-KEM hybrid KEX",
                             fix_steps=["Rebuild the tunnel on IKEv2 (vendor syntax, e.g. 'crypto ikev2 ...') with DH group 14+.",
                                        "Remove the IKEv1 configuration and re-audit.",
                                        "Track vendor ML-KEM hybrid-KEX support as the follow-up."]))
    if sshv == 1:
        rows.append(_row(asset_id, protocol="SSH", algorithm="SSHv1",
                         usage="remote admin", location="config",
                         klass="deprecated", pqc_status="MIGRATION_REQUIRED",
                         function="key-exchange",
                         risk="High — SSHv1 is classically broken and quantum-vulnerable",
                         priority="P1 — enforce SSHv2",
                         summary="SSH version 1 was found. It is fundamentally broken and must be disabled — this is a today problem, not a future one.",
                         migration="Enforce SSH version 2",
                         recommended="SSHv2 interim; then hybrid KEX (mlkem768x25519-sha256 on OpenSSH >= 9.9, else sntrup761x25519-sha512 on >= 9.0)",
                         fix_steps=["Enforce SSH version 2 (e.g. 'ip ssh version 2') and disable version 1.",
                                    "Use strong KEX/cipher settings, then re-audit.",
                                        "Enable hybrid post-quantum KEX (mlkem768x25519-sha256 preferred, sntrup761x25519-sha512 fallback)."]))
    for c in components:
        prod = f"{c.get('vendor','')}/{c.get('product','')}".lower()
        if any(k in prod for k in ("openssl", "openssh", "tls", "ipsec")):
            blob = f"{c.get('vendor','')} {c.get('product','')} {c.get('version','')}".lower()
            ver = str(c.get("version", "") or "")
            pname = str(c.get("product", "") or "crypto library")
            # Human-readable names: never show "openssh / openssh" style rows.
            if "openssh" in prod:
                friendly, proto, use = ("OpenSSH — SSH key exchange & host keys", "SSH",
                                        "remote admin (server/client software)")
                remedy = ["Check the version: 'ssh -V'. You need >= 9.0 for hybrid PQ key exchange (>= 9.9 for ML-KEM, 10.0+ uses mlkem768x25519-sha256 by default). Upgrade first if older.",
                          "Enable a hybrid KEX in sshd_config (e.g. 'KexAlgorithms +mlkem768x25519-sha256' on >= 9.9, else '+sntrup761x25519-sha512@openssh.com'), validate with 'sshd -t', then restart sshd.",
                          "Verify with 'ssh -v user@host' — the 'kex: algorithm:' line should show the hybrid algorithm. (OpenSSH >= 10.1 warns when a session is NOT using PQ key exchange.)",
                          "Host-key signatures stay classical RSA for now — PQ signatures (ML-DSA) are on the OpenSSH roadmap but not in a stable release. Keep host keys >= 3072 bits and rotate them on the new build, then re-audit."]
            elif "openssl" in prod:
                friendly, proto, use = ("OpenSSL — TLS / general crypto library", "TLS / general crypto",
                                        str(c.get("component_type", "") or "crypto library"))
                remedy = ["Upgrade to OpenSSL 3.2+ and enable the OQS provider (oqsprovider) for ML-KEM / ML-DSA hybrids.",
                          "Prefer hybrid TLS groups (e.g. X25519MLKEM768) where peers support them; keep classical groups for compatibility.",
                          "Re-issue long-lived certificates from a PQC-capable chain when your PKI supports it."]
            elif "ipsec" in prod:
                friendly, proto, use = (f"{pname} — IPsec stack", "IPsec / IKE",
                                        str(c.get("component_type", "") or "vpn software"))
                remedy = ["Stay on IKEv2 with DH group 14+.",
                          "Adopt the vendor's ML-KEM hybrid KEX option when published, then re-audit."]
            else:
                friendly, proto, use = (f"{pname} — TLS stack", "TLS",
                                        str(c.get("component_type", "") or "crypto software"))
                remedy = ["Upgrade to the vendor's PQC-capable release when published.",
                          "Prefer hybrid KEX options and keep classical for compatibility until peers support PQC."]
            if any(m in blob for m in PQC_MARKERS):
                rows.append(_row(asset_id, protocol=proto, algorithm=friendly,
                                 usage=use, location="inventory",
                                 klass="hybrid:pqc-ready", pqc_status="READY", version=ver,
                                 risk="Low — explicit PQC/hybrid support announced",
                                 priority="P3 — keep current",
                                 summary=f"{friendly}{f' {ver}' if ver else ''} advertises post-quantum / hybrid support. Nothing to migrate here — just stay updated.",
                                 migration="PQC/hybrid support present — keep updated",
                                 recommended="Stay on vendor PQC/hybrid releases",
                                 fix_steps=["No migration needed — keep this component on its current PQC-capable release train."]))
            else:
                rows.append(_row(asset_id, protocol=proto, algorithm=friendly,
                                 usage=use, location="inventory",
                                 klass="classical:quantum-vulnerable", pqc_status="TRANSITION",
                                 version=ver,
                                 risk="Medium — classical library; quantum-vulnerable KEX/signatures",
                                 priority="P2 — plan upgrade",
                                 summary=f"{friendly}{f' version {ver}' if ver else ' (version not detected in the config)'} handles encryption logins with classical key exchange. It works today but a future quantum computer could break the exchange — plan the vendor's hybrid upgrade.",
                                 migration="Track vendor PQC/hybrid roadmap",
                                 recommended="Upgrade to PQC-capable release (ML-KEM/ML-DSA) when available",
                                 fix_steps=remedy))
    if not rows:
        rows.append(_row(asset_id, protocol="—", algorithm="No crypto signals in config",
                         klass="unknown", pqc_status="UNKNOWN",
                         risk="Unknown — no inventory to assess",
                         priority="—",
                         summary="Neither the config nor the software inventory mentioned TLS, SSH, IKE, keys, or crypto libraries, so there is nothing to score.",
                         migration="Add crypto inventory",
                         recommended="Enable crypto inventory (TLS/IKE/SSH/key sizes) so readiness can be assessed",
                         fix_steps=["Make sure the uploaded config includes crypto sections (TLS, SSH, IKE, keys) and software versions, then re-run the audit."]))
    return rows


def readiness_label(score: float, counts: Dict[str, int]) -> str:
    if counts.get("MIGRATION_REQUIRED", 0) > 0 and score < 25:
        return "At risk"
    if score >= 85 and counts.get("READY", 0) > 0:
        return "On track"
    if score >= 60:
        return "Progressing"
    if score >= 25:
        return "Early transition"
    return "At risk"


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
    final = round(score / n, 1) if n else 0.0
    # Structured migration plan (also readable by older frontends: each entry
    # carries a plain-text "migration" string plus discrete fields).
    recs = [{"algorithm": r.get("algorithm"), "protocol": r.get("protocol"),
             "key_size": r.get("key_size"), "version": r.get("version", ""),
             "risk": r.get("risk", "") or _fallback("risk", r.get("pqc_status")),
             "priority": r.get("priority", "") or _fallback("priority", r.get("pqc_status")),
             "current": _current_of(r),
             "summary": r.get("summary", ""),
             "recommended_direction": r.get("recommended") or r.get("migration", ""),
             "fix_steps": r.get("fix_steps") or ([r.get("migration")] if r.get("migration") else []),
             "migration": r.get("migration", "")}
            for r in cbom if r.get("migration")]
    return {"readiness_score": final, "readiness": final,
            "readiness_label": readiness_label(final, counts),
            "counts": counts,
            "algorithms": cbom,
            "weak_algorithms": [r for r in cbom if r.get("pqc_status") == "MIGRATION_REQUIRED"],
            "migration_recommendations": recs}


def _fallback(field: str, status: Any) -> str:
    table = {
        "MIGRATION_REQUIRED": {"risk": "High — broken or deprecated; fix first",
                               "priority": "P1 — fix now"},
        "TRANSITION": {"risk": "Medium — secure today, quantum-vulnerable; plan migration",
                       "priority": "P2 — plan next"},
        "READY": {"risk": "Low — PQC/hybrid present",
                  "priority": "P3 — keep current"},
        "UNKNOWN": {"risk": "Unknown — not enough evidence to assess",
                    "priority": "—"},
    }
    return table.get(str(status), {}).get(field, "—")


def _heal_legacy_row(a: Dict[str, Any]) -> Dict[str, Any]:
    """Upgrade rows stored by older engines (e.g. algorithm/protocol both
    'openssh', no summary/fix_steps) to the current friendly shape so old
    audits read correctly without requiring a re-run. Only fills gaps —
    never overwrites existing detail."""
    algo = str(a.get("algorithm", "") or "")
    proto = str(a.get("protocol", "") or "")
    low = algo.lower()
    generic = low in ("openssh", "openssl", "tls", "ipsec") and proto.lower() == low
    if not generic or a.get("summary"):
        return a
    ver = str(a.get("version", "") or "")
    if low == "openssh":
        a["algorithm"] = "OpenSSH — SSH key exchange & host keys"
        a["protocol"] = "SSH"
        a["usage"] = a.get("usage") or "remote admin (server/client software)"
        a["summary"] = (f"OpenSSH software found in the device inventory"
                        f"{f' (version {ver})' if ver else ' (version not detected in the config)'}. "
                        "It handles SSH logins with classical key exchange: fine today, "
                        "breakable by a future quantum computer — plan the vendor's hybrid upgrade.")
        a["fix_steps"] = ["Check the version: 'ssh -V'. You need >= 9.0 for hybrid PQ key exchange (>= 9.9 for ML-KEM, 10.0+ uses mlkem768x25519-sha256 by default). Upgrade first if older.",
                          "Enable a hybrid KEX in sshd_config (e.g. 'KexAlgorithms +mlkem768x25519-sha256' on >= 9.9, else '+sntrup761x25519-sha512@openssh.com'), validate with 'sshd -t', then restart sshd.",
                          "Verify with 'ssh -v user@host' — the 'kex: algorithm:' line should show the hybrid algorithm.",
                          "Host-key signatures stay classical RSA for now — PQ signatures (ML-DSA) are on the OpenSSH roadmap but not in a stable release. Keep host keys >= 3072 bits, then re-audit."]
        a["recommended"] = a.get("recommended") or "Upgrade to PQC-capable release (ML-KEM/ML-DSA) when available"
    elif low == "openssl":
        a["algorithm"] = "OpenSSL — TLS / general crypto library"
        a["protocol"] = "TLS / general crypto"
        a["summary"] = (f"OpenSSL library found in the device inventory"
                        f"{f' (version {ver})' if ver else ' (version not detected)'}. "
                        "Classical TLS key exchange and signatures: fine today, quantum-vulnerable.")
        a["fix_steps"] = ["Upgrade to OpenSSL 3.2+ and enable the OQS provider (oqsprovider) for ML-KEM / ML-DSA hybrids.",
                          "Prefer hybrid TLS groups (e.g. X25519MLKEM768) where peers support them; keep classical groups for compatibility.",
                          "Re-issue long-lived certificates from a PQC-capable chain when your PKI supports it."]
        a["recommended"] = a.get("recommended") or "Upgrade to PQC-capable release (ML-KEM/ML-DSA) when available"
    elif low in ("tls", "ipsec"):
        a["algorithm"] = f"{algo} — {'TLS' if low == 'tls' else 'IPsec'} stack"
        a["protocol"] = "TLS" if low == "tls" else "IPsec / IKE"
        a["summary"] = (f"{algo} crypto software found in the inventory. Classical algorithms: "
                        "fine today, quantum-vulnerable — upgrade to the vendor's PQC-capable release when published.")
        a["fix_steps"] = ["Upgrade to the vendor's PQC-capable release when published.",
                          "Prefer hybrid KEX options and keep classical for compatibility until peers support PQC."]
    return a


def normalize_pqc_payload(p: Dict[str, Any]) -> Dict[str, Any]:
    """Backfill audits stored by older engine versions (e.g. recs as plain
    strings, rows without risk/priority/summary/fix_steps) into the current
    shape so the UI never renders blank Risk/Priority or a recommendation
    string in the 'Current' column. Purely additive — never drops keys."""
    p = dict(p or {})
    algos = [_heal_legacy_row(dict(a)) for a in (p.get("algorithms") or [])]
    for a in algos:
        st = a.get("pqc_status", "UNKNOWN")
        a.setdefault("risk", _fallback("risk", st))
        a.setdefault("priority", _fallback("priority", st))
        a.setdefault("summary", "")
        a.setdefault("recommended", a.get("migration", ""))
        if not a.get("fix_steps"):
            a["fix_steps"] = [a["migration"]] if a.get("migration") else []
        if not a.get("risk"):
            a["risk"] = _fallback("risk", st)
        if not a.get("priority"):
            a["priority"] = _fallback("priority", st)
    counts = p.get("counts") or {"READY": 0, "TRANSITION": 0, "MIGRATION_REQUIRED": 0, "UNKNOWN": 0}
    for a in algos:
        st = str(a.get("pqc_status", "UNKNOWN"))
        if st not in counts:
            counts[st] = 0
    # Recompute counts from rows when they look stale (e.g. missing keys).
    if not any(counts.values()) and algos:
        for a in algos:
            st = str(a.get("pqc_status", "UNKNOWN"))
            counts[st] = counts.get(st, 0) + 1
    score = p.get("readiness_score", p.get("readiness", 0.0))
    recs: List[Dict[str, Any]] = []
    for r in (p.get("migration_recommendations") or []):
        if isinstance(r, str):
            match = next((a for a in algos
                          if r == a.get("migration") or r == a.get("recommended")
                          or (r and a.get("migration") and r in str(a.get("migration")))), None)
            if match is None and algos:
                match = algos[0]
            if match is not None:
                recs.append({"algorithm": match.get("algorithm"), "protocol": match.get("protocol"),
                             "key_size": match.get("key_size"), "version": match.get("version", ""),
                             "risk": match.get("risk") or _fallback("risk", match.get("pqc_status")),
                             "priority": match.get("priority") or _fallback("priority", match.get("pqc_status")),
                             "current": _current_of(match), "summary": match.get("summary", ""),
                             "recommended_direction": match.get("recommended") or match.get("migration") or r,
                             "fix_steps": match.get("fix_steps") or [r], "migration": r})
            else:
                recs.append({"algorithm": "General crypto hygiene", "protocol": "—",
                             "key_size": None, "version": "", "risk": "—", "priority": "—",
                             "current": "General crypto hygiene", "summary": "",
                             "recommended_direction": r, "fix_steps": [r], "migration": r})
        elif isinstance(r, dict):
            d = dict(r)
            st = None
            for a in algos:
                if a.get("algorithm") == d.get("algorithm") and a.get("protocol") == d.get("protocol"):
                    st = a.get("pqc_status")
                    d.setdefault("summary", a.get("summary", ""))
                    d.setdefault("fix_steps", a.get("fix_steps", []))
                    break
            d.setdefault("risk", _fallback("risk", st))
            d.setdefault("priority", _fallback("priority", st))
            if not d.get("risk"):
                d["risk"] = _fallback("risk", st)
            if not d.get("priority"):
                d["priority"] = _fallback("priority", st)
            if not d.get("current"):
                d["current"] = str(d.get("algorithm") or d.get("migration") or "—")
            if not d.get("recommended_direction"):
                d["recommended_direction"] = str(d.get("recommended") or d.get("migration") or "—")
            if not d.get("fix_steps"):
                d["fix_steps"] = [d["migration"]] if d.get("migration") else []
            recs.append(d)
    out = dict(p)
    out["algorithms"] = algos
    out["counts"] = counts
    out.setdefault("readiness", score)
    out.setdefault("readiness_score", score)
    if not out.get("readiness_label"):
        try:
            if not algos and not recs and float(score or 0.0) == 0.0 and not any(counts.values()):
                # PQC engine never produced inventory (e.g. run_pqc=false on
                # an old audit): "At risk" would be a lie — nothing was assessed.
                out["readiness_label"] = "Not run"
            else:
                out["readiness_label"] = readiness_label(float(score or 0.0), counts)
        except Exception:
            out["readiness_label"] = "—"
    out["weak_algorithms"] = out.get("weak_algorithms") or [a for a in algos if a.get("pqc_status") == "MIGRATION_REQUIRED"]
    out["migration_recommendations"] = recs
    return out


def _current_of(r: Dict[str, Any]) -> str:
    algo = str(r.get("algorithm", "—"))
    extra = r.get("key_size") or r.get("version", "")
    return f"{algo}-{extra}" if extra else algo
