"""L2 Vendor Detection (arch.md §5) + version extraction.

Primary: models M1 (rules + TF-IDF LogReg). Fallback: local regex fingerprints
so the API works even if model artifacts are missing.
"""
from __future__ import annotations
import re
from typing import Any, Dict

from app.services.integration import fingerprint_vendor, m1_predict

# display names for the lower-case platform tokens used by the parsers / control applicability
PLATFORM_LABEL = {"ios": "IOS", "ios-xe": "IOS-XE", "nx-os": "NX-OS", "eos": "EOS", "junos": "Junos",
                  "fortios": "FortiOS", "pan-os": "PAN-OS"}

VERSION_PATTERNS = [
    # specific OS versions first — generic "version N" (e.g. `ip ssh version 1`)
    # must never beat the real platform version
    (r"ios(?:-xe)?\s*version\s*(\d+\.\d+[\.\w\-]*)", "IOS-XE"),
    (r"cisco\s+ios-xe\s+version\s*(\d+\.\d+[\.\w\-]*)", "IOS-XE"),
    # The gap between the platform name and its version is BOUNDED: an open-ended `[^\d]*` makes re.search quadratic on a
    # 5 MB config that repeats the platform word (e.g. "eos eos eos ...") with no digits anywhere (regex DoS).
    (r"junos[^\d]{0,40}(\d+\.\d+R\d+[\.\w\-]*)", "Junos"),
    (r"fortios[^\d]{0,40}v?(\d+\.\d+\.\d+)", "FortiOS"),
    (r"pan-os[^\d]{0,40}(\d+\.\d+[\.\w\-]*)", "PAN-OS"),
    (r"eos[^\d]{0,40}(\d+\.\d+[\.\w\-]*)", "EOS"),
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
    fp = fingerprint_vendor(config_text)
    platform_token = None
    if fp and float(fp["confidence"]) >= 0.9:
        # Structural markers beat the statistical model (trained on synthetic data).
        vendor, conf = str(fp["vendor"]), max(conf, float(fp["confidence"]))
        platform_token = str(fp["platform"])
        method = "fingerprint"
    else:
        method = m1.get("method", "rules")
    t = config_text.lower()
    version = fp.get("version") if fp else None
    for pat, _plat in VERSION_PATTERNS if not version else []:
        m = re.search(pat, t)
        if m:
            version = m.group(1).strip("v")
            break
    if vendor == "unknown":
        scores = {v: sum(1 for s in sigs if s in t) for v, sigs in VENDOR_HINTS.items()}
        best = max(scores, key=scores.get)
        if scores[best] > 0:
            vendor, conf = best, 0.62
    platform = PLATFORM_LABEL.get(platform_token or "", "") or _platform(vendor)
    return {"vendor": vendor.upper() if vendor != "unknown" else "UNKNOWN",
            "vendor_id": vendor, "platform": platform,
            "version": version, "confidence": round(conf, 3),
            "method": method}
