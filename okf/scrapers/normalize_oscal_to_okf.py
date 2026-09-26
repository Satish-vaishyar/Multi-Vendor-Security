"""Normalize scraped NIST OSCAL catalog into OKF control YAML (subset for network audit).

Reads knowledge/frameworks/NIST_OSCAL.json, maps in-scope families to canonical
properties, writes knowledge/controls/nist_oscal_subset.yaml. Idempotent.
Family→property map is curated; unmapped families are skipped (documented).
"""
from __future__ import annotations
import json
import re
from pathlib import Path
import yaml

ROOT = Path(__file__).parent.parent
SRC = ROOT / "knowledge" / "frameworks" / "NIST_OSCAL.json"
OUT = ROOT / "knowledge" / "controls" / "nist_oscal_subset.yaml"

# (regex on control id/title, canonical property, operator, value, severity, category)
RULES = [
    (r"AC-2\b", "AAA.AUTHENTICATION", "EQUALS", True, "HIGH", "authentication"),
    (r"AC-3\b", "ACL.MGMT_RESTRICTED", "EQUALS", True, "HIGH", "access_control"),
    (r"AC-7\b", "AAA.LOCKOUT_ENABLED", "EQUALS", True, "MEDIUM", "authentication"),
    (r"AC-8\b", "BANNER.LOGIN_SET", "EQUALS", True, "LOW", "system"),
    (r"AC-12\b|AC-11\b", "MGMT.SESSION_TIMEOUT", "EQUALS", True, "MEDIUM", "management"),
    (r"AC-17\b", "SSH.VERSION", "EQUALS", 2, "HIGH", "remote_access"),
    (r"AU-2\b|AU-3\b|AU-6\b", "LOGGING.ENABLED", "EQUALS", True, "MEDIUM", "logging"),
    (r"AU-4\b|AU-9\b", "LOGGING.REMOTE_SERVER", "EQUALS", True, "HIGH", "logging"),
    (r"AU-8\b", "NTP.ENABLED", "EQUALS", True, "MEDIUM", "system"),
    (r"CM-2\b|CM-6\b|CM-8\b", "AUDIT.CONFIG_ARCHIVED", "EQUALS", True, "LOW", "logging"),
    (r"CM-7\b", "TELNET.ENABLED", "EQUALS", False, "CRITICAL", "remote_access"),
    (r"IA-2\b", "AAA.AUTHENTICATION", "EQUALS", True, "HIGH", "authentication"),
    (r"IA-4\b", "USER.DEFAULT_ACCOUNTS", "EQUALS", False, "CRITICAL", "authentication"),
    (r"IA-5\b", "PASSWORD.ENCRYPTED", "EQUALS", True, "HIGH", "authentication"),
    (r"SC-7\b", "IP.SOURCE_ROUTE_DISABLED", "EQUALS", True, "HIGH", "network"),
    (r"SC-8\b", "MGMT.ENCRYPTED_ONLY", "EQUALS", True, "HIGH", "management"),
    (r"SC-10\b", "DOS.PROTECTION", "EQUALS", True, "MEDIUM", "network"),
    (r"SC-12\b", "CRYPTO.WEAK_ALGO", "EQUALS", False, "HIGH", "crypto"),
    (r"SC-17\b|SC-28\b", "KEY.STORED_SECURE", "EQUALS", True, "HIGH", "crypto"),
    (r"SI-2\b|SI-4\b", "MONITORING.NETFLOW", "EQUALS", True, "LOW", "monitoring"),
    (r"MA-4\b", "MGMT.ENCRYPTED_ONLY", "EQUALS", True, "MEDIUM", "management"),
    (r"PE-17\b", "CONSOLE.SECURED", "EQUALS", True, "MEDIUM", "remote_access"),
]


def _base_id(cid: str) -> str:
    m = re.match(r"([a-z]{2}-\d+)", cid or "", re.I)
    return m.group(1).upper() if m else (cid or "").upper()


def run() -> dict:
    data = json.loads(SRC.read_text(encoding="utf-8"))
    controls = data.get("controls", [])
    # group enhancements under base control
    by_base: dict[str, dict] = {}
    for c in controls:
        b = _base_id(c.get("id", ""))
        by_base.setdefault(b, c)
    out, used = [], set()
    for base, c in sorted(by_base.items()):
        for pat, prop, op, val, sev, cat in RULES:
            if re.search(pat, base):
                key = (base, prop)
                if key in used:
                    continue
                used.add(key)
                out.append({
                    "control_id": f"OKF-NIST-{base.replace('-', '')}",
                    "title": f"NIST {base}: {(c.get('title') or '').strip()}"[:160],
                    "description": f"OSCAL-normalized from NIST SP 800-53 Rev.5 {base}.",
                    "category": cat, "severity": sev, "version": "1.0",
                    "frameworks": {"NIST": base},
                    "condition": {"property": prop, "operator": op, "value": val},
                    "evidence_type": "CONFIGURATION",
                })
                break
    OUT.write_text(yaml.safe_dump({"controls": out}, sort_keys=False), encoding="utf-8")
    return {"generated": len(out), "out": str(OUT)}


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
