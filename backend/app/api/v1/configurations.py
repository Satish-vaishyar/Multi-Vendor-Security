"""Configurations: upload / bulk-upload / parse / get / canonical-ir / unknowns (api.md §6-9, §33)."""
from __future__ import annotations
from fastapi import APIRouter, File, Form, HTTPException, UploadFile
import re
from typing import List, Optional

from app.core import config as cfg
from app.core import persist as db
from app.core import store
from app.parsers import ingestion, vendor_detector, canonical as canon

router = APIRouter(prefix="/api/v1/configurations", tags=["configurations"])

# --- Critical-only human gate -------------------------------------------
# Only flag what is FULLY critical, needs human approval, and CANNOT be
# safely handled by AI. Everything else is auto-handled / ignored and never
# enters the training queue. This keeps the Training UI to true positives.
#
# Rationale:
#  - AI can handle: known/low-OOV lines, cosmetic lines (hostname, banner,
#    clock, version strings, descriptions), or lines the heuristic/LLM maps
#    with high confidence. Auto-mapping those is safe.
#  - Human required: security/routing-impact lines where a wrong mapping
#    causes outage or opens attack surface (routing auth, route leaks,
#    ACLs, crypto/AAA, mgmt access). AI must NOT auto-approve these.
CRITICAL_HUMAN_PATTERNS = [
    r"^\s*router\s+(ospf|bgp|eigrp|rip|isis)\b",
    r"^\s*(ip|ipv6)\s+route\b",
    r"^\s*neighbor\s+\S+\s+(remote-as|password|activate|peer-group|update-source)\b",
    r"^\s*network\s+\S+\s+(area|backbone)\b",
    r"^\s*redistribute\b",
    r"^\s*(route-map|prefix-list|distribute-list|offset-list)\b",
    r"^\s*(access-list|ip\s+access-group|permit\s+ip\s+any|deny\s+ip\s+any)\b",
    r"^\s*crypto\s+(key|ike|ipsec|isakmp|pki)\b",
    r"^\s*aaa\s+(authentication|authorization|accounting)\b",
    r"^\s*(tacacs-server|radius-server|tacacs\s+server|radius\s+server)\b",
    r"^\s*(enable\s+(secret|password)|username\s+\S+\s+(privilege|secret|password))\b",
    r"^\s*snmp-server\s+(community|host|group|user)\b",
    r"^\s*(line\s+vty|transport\s+input|login\s+(local|authentication))\b",
    r"^\s*(key\s+chain|authentication\s+key-chain|ip\s+ospf\s+authentication|area\s+\S+\s+authentication)\b",
    r"^\s*(zone-pair|policy-map\s+type\s+inspect|ip\s+inspect)\b",
]
_CRITICAL_RE = re.compile("|".join(f"(?:{p})" for p in CRITICAL_HUMAN_PATTERNS), re.IGNORECASE)

# Cosmetic / low-risk lines AI can safely handle or ignore outright.
COSMETIC_RE = re.compile(
    r"^\s*(hostname|banner\s+(motd|login|exec)|clock\s+(timezone|summer-time)|"
    r"service\s+timestamps|logging\s+(buffered|trap|console|monitor)|"
    r"description\b|.*Cisco\s+IOS.*version|.*software\s+version|"
    r"ip\s+domain-name|ip\s+name-server|ntp\s+clock-period)\b",
    re.IGNORECASE,
)


def _needs_human_approval(line: str, oov: dict) -> tuple[bool, str]:
    """True only if fully critical, AI can't handle it, needs human approval."""
    s = (line or "").strip()
    if not s:
        return False, "empty"
    if COSMETIC_RE.search(s):
        return False, "cosmetic/auto-handled"
    # AI can handle anything the OOV model already calls known (low novelty).
    if (oov or {}).get("label") == "known":
        return False, "ai-handled:low-oov"
    # Only security/routing-impact lines escalate to a human.
    if not _CRITICAL_RE.search(s):
        return False, "non-critical/auto-handled"
    return True, "critical:routing/security-impact:needs-human-approval"


def _register(filename: str, content: bytes, asset_id: str, hint_vendor: str = "", hint_platform: str = "") -> dict:
    v = ingestion.validate_upload(filename, content)
    det = vendor_detector.detect_vendor(v["text"], hint_vendor)
    cid = store.nid("CFG")
    rec = {"configuration_id": cid, "asset_id": asset_id, "filename": filename,
           "size": v["size"], "lines": v["lines"], "sha256": v["sha256"],
           "config_text": v["text"], "warnings": v["warnings"],
           "detected_vendor": det["vendor"], "detected_platform": det["platform"],
           "detected_version": det.get("version"), "detection": det,
           "hint_vendor": hint_vendor, "hint_platform": hint_platform,
           "status": "UPLOADED", "created_at": store.now()}
    db.save("configurations", rec)
    return rec


@router.post("/upload")
async def upload(file: UploadFile = File(...), asset_id: str = Form("AST-001"),
                 vendor: str = Form(""), platform: str = Form("")):
    content = await file.read()
    try:
        rec = _register(file.filename or "config.txt", content, asset_id, vendor, platform)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return cfg.ok({"configuration_id": rec["configuration_id"], "filename": rec["filename"],
                   "size": rec["size"], "status": rec["status"],
                   "detected_vendor": rec["detected_vendor"],
                   "detected_platform": rec["detected_platform"],
                   "detected_version": rec["detected_version"]}, "Upload successful")


@router.post("/bulk-upload")
async def bulk_upload(files: List[UploadFile] = File(...), asset_id: str = Form("AST-001")):
    if len(files) > cfg.MAX_BULK_FILES:
        raise HTTPException(400, f"Too many files (max {cfg.MAX_BULK_FILES})")
    batch_id = store.nid("BATCH")
    out, rejected = [], 0
    for f in files:
        try:
            rec = _register(f.filename or "config.txt", await f.read(), asset_id)
            out.append({"configuration_id": rec["configuration_id"], "status": "QUEUED"})
        except ValueError:
            rejected += 1
    return cfg.ok({"batch_id": batch_id, "total_files": len(files),
                   "accepted": len(out), "rejected": rejected, "configurations": out})


@router.post("/{configuration_id}/parse")
def parse(configuration_id: str):
    rec = db.get("configurations", configuration_id)
    if not rec:
        raise HTTPException(404, "Configuration not found")
    parsed = canon.parse_to_canonical(rec["config_text"], rec["detection"]["vendor_id"])
    rec = db.update("configurations", configuration_id,
                    {"status": "PARSED", "canonical_ir": parsed["nested_ir"],
                     "flat_ir": parsed["flat_ir"], "unknown_lines": parsed["unknown_lines"]})
    assert rec is not None
    return cfg.ok({"job_id": store.nid("JOB"), "status": "COMPLETED",
                   "configuration_id": configuration_id}, "Parse completed")


@router.get("/{configuration_id}")
def get_configuration(configuration_id: str):
    rec = db.get("configurations", configuration_id)
    if not rec:
        raise HTTPException(404, "Configuration not found")
    view = {k: v for k, v in rec.items() if k != "config_text"}
    view["parser"] = {"type": "KNOWN_VENDOR" if rec["detected_vendor"] != "UNKNOWN" else "AI_PIPELINE",
                      "confidence": rec["detection"]["confidence"]}
    return cfg.ok(view)


@router.get("/{configuration_id}/canonical-ir")
def get_canonical(configuration_id: str):
    rec = db.get("configurations", configuration_id)
    if not rec:
        raise HTTPException(404, "Configuration not found")
    if "canonical_ir" not in rec:
        parsed = canon.parse_to_canonical(rec["config_text"], rec["detection"]["vendor_id"])
        rec = db.update("configurations", configuration_id,
                        {"canonical_ir": parsed["nested_ir"], "flat_ir": parsed["flat_ir"]})
        assert rec is not None
    return cfg.ok(rec["canonical_ir"])


@router.get("/{configuration_id}/unknowns")
def get_unknowns(configuration_id: str):
    rec = db.get("configurations", configuration_id)
    if not rec:
        raise HTTPException(404, "Configuration not found")
    parsed = canon.parse_to_canonical(rec["config_text"], rec["detection"]["vendor_id"])
    from app.services.integration import m2_score_batch
    scores = m2_score_batch(parsed["unknown_lines"])
    # Critical-only gate: flag ONLY what is fully critical, needs human
    # approval, and can't be handled by AI. Everything else is auto-handled.
    critical_items = []
    auto_handled = 0
    for i, l in enumerate(parsed["unknown_lines"]):
        oov = scores[i] if i < len(scores) else {}
        needs_human, reason = _needs_human_approval(l, oov)
        if not needs_human:
            auto_handled += 1
            continue
        critical_items.append({"id": f"UNK-{i + 1:03d}", "line": l, "context": [],
                               "status": "NEEDS_HUMAN_APPROVAL",
                               "reason": reason, "oov": oov})
    # Sync ONLY critical items into the training queue (dedupe on re-GET).
    try:
        existing = {t.get("raw_command") for t in db.find("training", status="PENDING")}
    except Exception:
        existing = set()
    for it in critical_items:
        if it["line"] in existing:
            continue
        tid = store.nid("TR")
        db.save("training", {"training_id": tid, "vendor": rec["detected_vendor"],
                             "platform": rec["detected_platform"], "raw_command": it["line"],
                             "context": [], "status": "PENDING",
                             "reason": it["reason"], "created_at": store.now()})
        existing.add(it["line"])
    return cfg.ok({"unknown_count": len(parsed["unknown_lines"]),
                   "critical_count": len(critical_items),
                   "auto_handled": auto_handled,
                   # `items` is now critical-only (was: every unknown line).
                   "items": critical_items})
