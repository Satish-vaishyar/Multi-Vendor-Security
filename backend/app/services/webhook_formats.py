"""Receiver-specific webhook body formats: CEF (SIEM), Jira issue-create, ServiceNow incident.

Only summaries and ids are ever placed in a body (see ``facts``): no configuration text, evidence lines,
secrets or the receiver credential. Every value that originates in user-controlled data (asset names, job errors)
is stripped of control characters and escaped for the target syntax.
"""
from __future__ import annotations
import re
import time
from typing import Any, Dict

from app.core import config as cfg

FACT_KEYS = ("asset_id", "asset_name", "audit_id", "compliance_score", "failed", "job_id", "kind")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")      # control characters other than \t \n \r
CEF_SEVERITY = {"audit.completed": 3, "finding.new_critical_high": 8, "job.failed": 6, "ping": 1}   # CEF scale 0-10
_NAMES = {"audit.completed": "Audit completed", "finding.new_critical_high": "New critical/high finding",
          "job.failed": "Background job failed"}


def facts(d: Dict[str, Any]) -> Dict[str, Any]:
    """Whitelisted scalar facts of an event payload."""
    out: Dict[str, Any] = {k: d[k] for k in FACT_KEYS
                           if isinstance(d.get(k), (str, int, float)) and not isinstance(d.get(k), bool)}
    ch = d.get("changes") if isinstance(d.get("changes"), dict) else {}
    for k in ("new", "resolved", "new_critical_high"):
        if isinstance(ch.get(k), int) and not isinstance(ch.get(k), bool):
            out[f"changes_{k}"] = ch[k]
    return out


def clean(v: Any, limit: int = 500) -> str:
    return _CTRL.sub(" ", str(v))[:limit]


def cef_header(v: Any) -> str:
    """Escape a CEF header field: backslash and pipe. Line breaks can never appear in a header."""
    s = clean(v).replace("\r", " ").replace("\n", " ")
    return s.replace("\\", "\\\\").replace("|", "\\|")


def cef_ext(v: Any) -> str:
    """Escape a CEF extension VALUE: backslash, '=' and line breaks.

    An unescaped '=' lets a value forge extra key=value pairs and an unescaped newline lets it forge a whole event."""
    s = _CTRL.sub(" ", str(v))[:1000]
    s = s.replace("\\", "\\\\").replace("=", "\\=")
    return s.replace("\r\n", "\\n").replace("\n", "\\n").replace("\r", "\\n")


def render_cef(event: str, envelope: Dict[str, Any], headline: str) -> str:
    """One CEF line: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension."""
    d = envelope["data"]
    f = facts(d)
    ext: list = [("rt", int(time.time() * 1000)), ("externalId", envelope.get("id", "")), ("cat", event),
                 ("cs1Label", "orgId"), ("cs1", envelope.get("org_id", "")), ("msg", headline)]
    for key, label, field in (("cs2", "assetId", "asset_id"), ("cs3", "auditId", "audit_id"), ("cs4", "jobId", "job_id")):
        if field in f:
            ext += [(f"{key}Label", label), (key, f[field])]
    if "failed" in f:
        ext += [("cn1Label", "failedControls"), ("cn1", f["failed"])]
    if "changes_new_critical_high" in f:
        ext += [("cn2Label", "newCriticalHigh"), ("cn2", f["changes_new_critical_high"])]
    head = "|".join(["CEF:0"] + [cef_header(x) for x in ("NSCA", "Network Security Compliance Auditor", "1.0", event,
                                                          _NAMES.get(event, "Webhook test"))])
    return f"{head}|{CEF_SEVERITY.get(event, 3)}|" + " ".join(f"{k}={cef_ext(v)}" for k, v in ext)


def _lines(event: str, envelope: Dict[str, Any], headline: str) -> list:
    f = facts(envelope["data"])
    return [clean(headline, 1000), "", f"Event: {event}", f"Delivery: {envelope.get('id', '')}"] + \
           [f"{k}: {clean(v, 200)}" for k, v in f.items()]


def render_jira(event: str, envelope: Dict[str, Any], headline: str) -> Dict[str, Any]:
    """Body for POST <jira>/rest/api/2/issue (Jira Cloud and Server/Data Center)."""
    return {"fields": {"project": {"key": cfg.WEBHOOK_JIRA_PROJECT},
                       "issuetype": {"name": cfg.WEBHOOK_JIRA_ISSUE_TYPE},
                       "summary": clean(headline, 250).replace("\n", " "),
                       "description": "\n".join(_lines(event, envelope, headline)),
                       "labels": ["nsca", event.replace(".", "-")]}}


def render_servicenow(event: str, envelope: Dict[str, Any], headline: str) -> Dict[str, Any]:
    """Body for POST <instance>/api/now/table/incident (Table API). urgency/impact: 1 high, 2 medium, 3 low."""
    urgency = {"finding.new_critical_high": "1", "job.failed": "2"}.get(event, "3")
    return {"short_description": clean(headline, 160).replace("\n", " "),
            "description": "\n".join(_lines(event, envelope, headline)),
            "category": "Security", "urgency": urgency, "impact": urgency,
            "correlation_id": str(envelope.get("id", ""))[:100], "contact_type": "integration"}
