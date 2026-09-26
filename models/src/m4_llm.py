"""M4 LLM Parser: pretrained LLM only, structured JSON, low-temp. Reuses okf llm_gateway if present."""
from __future__ import annotations
import json, re
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.common import CANONICAL_PROPERTIES

SYS = ("Convert network config lines to JSON mappings. "
       "Only output: [{\"property\": <one of canonical>, \"value\": ..., \"confidence\": 0-1, \"evidence\": <line>}]. "
       "Never output security verdicts.")


def _heuristic(config: str):
    maps = []
    for ln in config.splitlines():
        s = ln.strip()
        if not s or s.startswith(("!", "#")):
            continue
        low = s.lower()
        if "ssh" in low and ("v2" in low or "version 2" in low):
            maps.append({"property": "services.ssh.version", "value": 2, "confidence": 0.85, "evidence": s})
        elif "telnet" in low and any(w in low for w in ("deny", "disable", "no ", "delete")):
            maps.append({"property": "services.telnet", "value": False, "confidence": 0.8, "evidence": s})
        elif "telnet" in low:
            maps.append({"property": "services.telnet", "value": True, "confidence": 0.8, "evidence": s})
        elif "http" in low and any(w in low for w in ("no ", "disable", "delete")):
            maps.append({"property": "services.http", "value": False, "confidence": 0.8, "evidence": s})
        elif "syslog" in low or "logging host" in low or "event-sink remote" in low:
            maps.append({"property": "logging.enabled", "value": True, "confidence": 0.8, "evidence": s})
    return {"mappings": maps, "offline": True}


def parse(config: str, vendor: str = "unknown"):
    # 1) try okf gateway (single-file LLM rule)
    try:
        sys.path.insert(0, "F:/Multi-vendor/okf")
        from llm_gateway import parse_config_to_ir
        r = parse_config_to_ir(config, vendor=vendor)
        # normalize keys to models.md §11 format
        maps = [{"property": m.get("canonical_property"), "value": m.get("canonical_value"),
                 "confidence": m.get("confidence", 0.8), "evidence": m.get("evidence", "")}
                for m in r.get("mappings", [])]
        return {"mappings": maps, "offline": r.get("offline", False)}
    except Exception:
        return _heuristic(config)
