"""Engine 3 — Security Analytics (arch.md §19-20). Rules + combination patterns.

Detects posture issues (not framework verdicts): weak auth, exposure,
permissive ACLs, legacy services, logging gaps, drift hints — plus a
combination pattern 'Exposed Administrative Access' when several moderate
signals coincide.
"""
from __future__ import annotations
from typing import Any, Dict, List


def analyze(flat: Dict[str, Any], asset_id: str = "") -> Dict[str, Any]:
    anomalies: List[Dict[str, Any]] = []

    def add(atype: str, prop: str, sev: str, detail: str = ""):
        anomalies.append({"type": atype, "property": prop, "severity": sev,
                          "asset_id": asset_id, "detail": detail})

    if flat.get("TELNET.ENABLED") is True:
        add("LEGACY_SERVICE", "TELNET.ENABLED", "HIGH", "Cleartext remote admin enabled")
    if flat.get("HTTP.ENABLED") is True:
        add("LEGACY_SERVICE", "HTTP.ENABLED", "MEDIUM", "Unencrypted web management enabled")
    if flat.get("SSH.VERSION") == 1:
        add("WEAK_CRYPTO", "SSH.VERSION", "HIGH", "SSHv1 in use")
    if flat.get("CRYPTO.WEAK_ALGO") is True:
        add("WEAK_CRYPTO", "CRYPTO.WEAK_ALGO", "HIGH", "DES/3DES/RC4/MD5/SHA1/DH-group1 present")
    if flat.get("SNMP.COMMUNITY_PUBLIC") is True:
        add("WEAK_CREDENTIAL", "SNMP.COMMUNITY_PUBLIC", "HIGH", "Default SNMP community 'public'")
    if flat.get("PASSWORD.ENCRYPTED") is False:
        add("WEAK_CREDENTIAL", "PASSWORD.ENCRYPTED", "HIGH", "Cleartext passwords stored")
    if flat.get("LOGGING.ENABLED") is False:
        add("LOGGING_GAP", "LOGGING.ENABLED", "MEDIUM", "Device logging disabled")
    if flat.get("LOGGING.REMOTE_SERVER") is False or flat.get("LOGGING.ENABLED") is False:
        add("LOGGING_GAP", "LOGGING.REMOTE_SERVER", "MEDIUM", "No remote syslog — no tamper-resistant audit trail")
    if flat.get("AAA.AUTHENTICATION") is False:
        add("WEAK_AUTH", "AAA.AUTHENTICATION", "HIGH", "No AAA authentication")
    if flat.get("ACL.MGMT_RESTRICTED") is False:
        add("PERMISSIVE_ACCESS", "ACL.MGMT_RESTRICTED", "MEDIUM", "Management plane not ACL-restricted")
    if flat.get("ACL.PERMIT_ANY") is True:
        add("PERMISSIVE_ACCESS", "ACL.PERMIT_ANY", "HIGH", "permit ip any any present")
    if flat.get("MGMT.INTERNET_EXPOSED") is True:
        add("EXPOSURE", "MGMT.INTERNET_EXPOSED", "CRITICAL", "Management interface internet-facing")

    # Combination: exposed administrative access pattern (§20)
    combo_signals = [
        flat.get("SSH.ENABLED") in (True, None) or flat.get("SSH.VERSION") is not None,
        flat.get("AAA.MFA") in (False, None),
        flat.get("MGMT.INTERNET_EXPOSED") is True or flat.get("ACL.MGMT_RESTRICTED") is False,
    ]
    patterns = []
    if sum(1 for s in combo_signals if s) >= 2 and flat.get("TELNET.ENABLED") is True:
        patterns.append({"pattern": "Exposed Administrative Access",
                         "severity": "CRITICAL",
                         "detail": "Telnet/cleartext admin + weak AAA boundary — treat as high-priority exposure",
                         "contributors": ["TELNET.ENABLED", "AAA.MFA", "ACL.MGMT_RESTRICTED"]})
    score = 100
    for a in anomalies:
        score -= {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2}.get(a["severity"], 5)
    for p in patterns:
        score -= 15
    return {"risk_score": max(0, min(100, score)), "anomalies": anomalies,
            "patterns": patterns, "count": len(anomalies) + len(patterns)}
