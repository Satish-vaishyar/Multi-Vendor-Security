"""Logging setup: text (default) or JSON lines (LOG_FORMAT=json), always with secret redaction.

JSON records carry: ts, level, logger, msg, request_id, org_id (+ exc on errors). Secrets are scrubbed from the
message and the traceback by the shared redaction rules plus a few key=value / bearer-token patterns.
"""
from __future__ import annotations
import contextvars
import json
import logging
import re
import sys
from datetime import datetime, timezone

from app.core import config as cfg

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="")

_KV = re.compile(r"(?i)\b(password|passwd|passphrase|secret|token|api[_-]?key|authorization|jwt|cookie)\b(\s*[=:]\s*)(bearer\s+)?[^\s,;&\"'}]+")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")


def scrub(text: str) -> str:
    try:
        from app.core.redact import redact_secrets
        text = redact_secrets(text)
    except Exception:  # noqa: BLE001 - never let redaction failure break logging
        pass
    text = _JWT.sub("[REDACTED]", text)
    text = _BEARER.sub("Bearer [REDACTED]", text)
    return _KV.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)


class RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = scrub(record.getMessage())
            record.args = ()
        except Exception:  # noqa: BLE001
            pass
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        org = getattr(record, "org_id", None)
        if not org:
            try:
                from app.core import tenancy
                org = tenancy._org.get()
            except Exception:  # noqa: BLE001
                org = None
        doc = {"ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
               "level": record.levelname, "logger": record.name, "msg": scrub(record.getMessage()),
               "request_id": getattr(record, "request_id", None) or request_id_var.get() or None,
               "org_id": org}
        if record.exc_info:
            doc["exc"] = scrub(self.formatException(record.exc_info))
        return json.dumps(doc, default=str)


def configure(fmt: str | None = None) -> None:
    """Idempotent: (re)install a single stderr handler on the root logger."""
    fmt = (fmt or cfg.LOG_FORMAT or "text").lower()
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in list(root.handlers):
        if getattr(h, "_auditor", False):
            root.removeHandler(h)
    handler = logging.StreamHandler(sys.stderr)
    handler._auditor = True  # type: ignore[attr-defined]
    handler.addFilter(RedactFilter())
    handler.setFormatter(JsonFormatter() if fmt == "json"
                         else logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    root.addHandler(handler)
