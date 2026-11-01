"""L1 Ingestion: validation + sanitization + metadata + SHA-256 (arch.md §4)."""
from __future__ import annotations
import hashlib
import os
from typing import Any, Dict

ALLOWED_EXT = {".txt", ".cfg", ".conf", ".json", ".xml", ".text", ".log"}
MAX_BYTES = 5 * 1024 * 1024
# Parsing cost grows with the number of lines (every line is matched against hundreds of rules, unknown lines are
# embedded by the ML models): 100,000 lines is far beyond any real device configuration and keeps a hostile
# 5 MB file of one-character lines from occupying a worker for minutes.
MAX_LINES = int(os.getenv("MAX_CONFIG_LINES", "100000"))


def validate_upload(filename: str, content: bytes) -> Dict[str, Any]:
    ext = "." + (filename.rsplit(".", 1)[-1].lower() if "." in filename else "")
    issues = []
    if ext not in ALLOWED_EXT:
        issues.append(f"extension {ext or '(none)'} not in {sorted(ALLOWED_EXT)} (accepted anyway as text)")
    if len(content) > MAX_BYTES:
        raise ValueError(f"file too large: {len(content)} > {MAX_BYTES}")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = content.decode("utf-8", errors="replace")
        issues.append("non-utf8 bytes replaced")
    if not text.strip():
        raise ValueError("empty configuration")
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        raise ValueError(f"too many lines: {len(lines)} > {MAX_LINES}")
    digest = hashlib.sha256(text.encode()).hexdigest()
    return {"filename": filename, "size": len(content), "lines": len(lines),
            "sha256": digest, "text": text, "warnings": issues}
