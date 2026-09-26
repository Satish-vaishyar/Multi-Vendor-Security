"""L2 Vendor Detection (arch.md §5) + version extraction.

Primary: models M1 (rules + TF-IDF LogReg). Fallback: local regex fingerprints
so the API works even if model artifacts are missing.
"""
from __future__ import annotations
import re
from typing import Any, Dict

from app.services.integration import m1_predict

VERSION_PATTERNS = [
    # specific OS versions first — generic "version N" (e.g. `ip ssh version 1`)
    # must never beat the real platform version
    (r"ios(?:-xe)?\s*version\s*(\d+\.\d+[\.\w\-]*)", "IOS-XE"),
    (r"cisco\s+ios-xe\s+version\s*(\d+\.\d+[\.\w\-]*)", "IOS-XE"),
    (r"junos[^\d]*(\d+\.\d+R\d+[\.\w\-]*)", "Junos"),
    (r"fortios[^\d]*v?(\d+\.\d+\.\d+)", "FortiOS"),
    (r"pan-os[^\d]*(\d+\.\d+[\.\w\-]*)", "PAN-OS"),
    (r"eos[^\d]*(\d+\.\d+[\.\w\-]*)", "EOS"),
    (r"(?<![\w-])version\s+(\d+\.\d+[\.\d\w\-\.]*)\b", None),
]

VENDOR_HINTS = {
    "cisco": ["gigabitethernet", "snmp-server", "line vty", "ip ssh version", "aaa new-model", "service password-encryption"],
    "juniper": ["set system services", "set interfaces", "junos"],
    "fortinet": ["config system", "fortios", "fortigate", "set allowaccess"],
    "paloalto": ["set deviceconfig", "pan-os", "vsys"],
    "arista": ["daemon terminattr", "switchport", "management api"],
}


def _platform(vendor: str) -> str:
    return {"cisco": "IOS-XE", "juniper": "Junos", "fortinet": "FortiOS",
            "paloalto": "PAN-OS", "arista": "EOS"}.get(vendor, "UNKNOWN")


def detect_vendor(config_text: str, hint_vendor: str = "") -> Dict[str, Any]:
    m1 = m1_predict(config_text)
    vendor = str(m1.get("vendor", "unknown")).lower()
    conf = float(m1.get("confidence", 0.31) or 0.31)
    if hint_vendor and vendor in ("unknown",):
        vendor, conf = hint_vendor.lower(), 0.6
    t = config_text.lower()
    version = None
    for pat, _plat in VERSION_PATTERNS:
        m = re.search(pat, t)
        if m:
            version = m.group(1).strip("v")
            break
    if vendor == "unknown":
        scores = {v: sum(1 for s in sigs if s in t) for v, sigs in VENDOR_HINTS.items()}
        best = max(scores, key=scores.get)
        if scores[best] > 0:
            vendor, conf = best, 0.62
    return {"vendor": vendor.upper() if vendor != "unknown" else "UNKNOWN",
            "vendor_id": vendor, "platform": _platform(vendor),
            "version": version, "confidence": round(conf, 3),
            "method": m1.get("method", "rules")}
