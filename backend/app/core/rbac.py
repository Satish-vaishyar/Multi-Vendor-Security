"""Role-based access control: one auditable permission matrix.

Roles are hierarchical:  VIEWER < AUDITOR < APPROVER < ADMIN

  VIEWER   read everything in the own org (configs are shown redacted)
  AUDITOR  VIEWER + upload configs, run audits/reports, manage assets, ask the AI for suggestions
  APPROVER AUDITOR + approve/reject learned mappings and remediation, delete assets
  ADMIN    APPROVER + users, CVE sync, audit log, bulk maintenance

``required_role(method, path)`` is the single source of truth, applied to every
/api/v1 route by ``security.enforce_permissions``. Unlisted reads need VIEWER,
unlisted writes need AUDITOR. tests/test_rbac.py walks every registered route.
"""
from __future__ import annotations
import re
from typing import List, Tuple

VIEWER, AUDITOR, APPROVER, ADMIN = "VIEWER", "AUDITOR", "APPROVER", "ADMIN"
ROLES: List[str] = [VIEWER, AUDITOR, APPROVER, ADMIN]
_RANK = {r: i for i, r in enumerate(ROLES)}

# (method, compiled path regex, minimum role) - first match wins.
_RULES: List[Tuple[str, "re.Pattern[str]", str]] = [(m, re.compile(p), r) for m, p, r in [
    # --- administration ---------------------------------------------------
    ("GET",    r"^/api/v1/admin/.*$",                              ADMIN),
    ("POST",   r"^/api/v1/admin/.*$",                              ADMIN),
    ("PATCH",  r"^/api/v1/admin/.*$",                              ADMIN),
    ("DELETE", r"^/api/v1/admin/.*$",                              ADMIN),
    ("POST",   r"^/api/v1/vulnerabilities/sync$",                  ADMIN),
    ("POST",   r"^/api/v1/assets/merge-duplicates$",               ADMIN),
    ("GET",    r"^/api/v1/collection/credentials.*$",              ADMIN),
    ("POST",   r"^/api/v1/collection/credentials$",                ADMIN),
    ("DELETE", r"^/api/v1/collection/credentials/[^/]+$",          ADMIN),
    ("PUT",    r"^/api/v1/assets/[^/]+/collection$",               ADMIN),
    ("POST",   r"^/api/v1/assets/[^/]+/collection/scan-host-key$", ADMIN),
    ("GET",    r"^/api/v1/integrations/.*$",                       ADMIN),
    ("POST",   r"^/api/v1/integrations/.*$",                       ADMIN),
    ("PATCH",  r"^/api/v1/integrations/.*$",                       ADMIN),
    ("DELETE", r"^/api/v1/integrations/.*$",                       ADMIN),
    # --- decisions that change what future audits/fixes say ---------------
    ("POST",   r"^/api/v1/training/[^/]+/(approve|reject)$",       APPROVER),
    ("POST",   r"^/api/v1/remediation/[^/]+/(approve|apply)$",     APPROVER),
    ("POST",   r"^/api/v1/remediation-verifications$",             APPROVER),
    ("DELETE", r"^/api/v1/assets/[^/]+$",                          APPROVER),
    ("POST",   r"^/api/v1/reports/[^/]+/signoff$",                 APPROVER),
    ("POST",   r"^/api/v1/exceptions/[^/]+/(approve|reject|revoke)$", APPROVER),
    # --- POSTs that only compute/read -------------------------------------
    ("POST",   r"^/api/v1/detection/vendor$",                      VIEWER),
    ("POST",   r"^/api/v1/vulnerabilities/blast-radius$",          VIEWER),
]]


def rank(role: str) -> int:
    return _RANK.get(str(role or "").upper(), -1)


def has_role(user_role: str, minimum: str) -> bool:
    return rank(user_role) >= rank(minimum) >= 0


def required_role(method: str, path: str) -> str:
    method = method.upper()
    for m, rx, role in _RULES:
        if m == method and rx.match(path):
            return role
    return VIEWER if method in ("GET", "HEAD", "OPTIONS") else AUDITOR
