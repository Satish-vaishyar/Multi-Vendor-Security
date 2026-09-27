"""Software inventory extractor: config → software_components[] (cve_okf §11).

Deterministic regex first; LLM (llm_gateway only) fills gaps. Adds:
- OS component (vendor/product/version from banner/version lines)
- Service components (SSH/TLS hints)
"""
from __future__ import annotations
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

OS_PATTERNS = [
    (r"cisco\s+ios[-\s]?xe[^\d]*(\d[\w.\-()]+)", "cisco", "ios-xe"),
    (r"cisco\s+ios[^\d]*(\d[\w.\-()]+)", "cisco", "ios"),
    (r"version\s+(\d+\.\d+[\w.\-()]*).*ios[-\s]?xe", "cisco", "ios-xe"),
    (r"\bversion\s+(\d[\w.\-()]+)", None, None),  # generic fallback
    (r"junos[\s:]+([\d.r\-]+)", "juniper", "junos"),
    (r"fortios[^\d]*v?(\d[\w.\-]+)", "fortinet", "fortios"),
    (r"pan-os[^\d]*(\d[\w.\-]+)", "paloalto", "pan-os"),
    (r"eos[^\d]*(\d[\w.\-]+)", "arista", "eos"),
]


def extract(config_text: str, default_vendor: str = "cisco",
            default_product: str = "") -> List[Dict[str, Any]]:
    comps: List[Dict[str, Any]] = []
    seen = set()
    for pat, vendor, product in OS_PATTERNS:
        for m in re.finditer(pat, config_text, re.I):
            v, p = vendor or default_vendor, product or default_product or "unknown"
            ver = m.group(1)
            key = (v, p, ver)
            if key in seen:
                continue
            seen.add(key)
            comps.append({"vendor": v, "product": p, "version": ver,
                          "component_type": "operating_system", "cpe": None,
                          "source": "config_regex"})
    # service hints: only emit a component when there is concrete evidence of
    # the implementation AND its version (e.g. an SSH banner "SSH-2.0-OpenSSH_8.9").
    # A bare "ssh" keyword (e.g. "ip ssh version 2" on Cisco IOS, where SSH is
    # part of the OS — not OpenBSD OpenSSH) must not fabricate an unversioned
    # component: it can never be correlated and only surfaces as UNKNOWN rows.
    for m in re.finditer(r"OpenSSH[_/](\d[\w.\-]+)", config_text):
        ver = m.group(1)
        key = ("openbsd", "openssh", ver)
        if key in seen:
            continue
        seen.add(key)
        comps.append({"vendor": "openbsd", "product": "openssh", "version": ver,
                      "component_type": "service", "cpe": None,
                      "source": "service_banner"})
    return comps
