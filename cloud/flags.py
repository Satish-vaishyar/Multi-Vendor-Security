"""Feature flag for the cloud module (RTM CM-150).

Fail-closed: the module is OFF unless the variable is explicitly set to an affirmative value. A typo, an empty
string or an unexpected value never turns it on.
"""
from __future__ import annotations

import os
from typing import Mapping, Optional

ENV_VAR = "CLOUD_MODULE_ENABLED"
_TRUE = frozenset({"1", "true", "yes", "on"})


def is_enabled(env: Optional[Mapping[str, str]] = None) -> bool:
    """True only when CLOUD_MODULE_ENABLED is exactly one of 1/true/yes/on (case-insensitive, trimmed)."""
    source = os.environ if env is None else env
    return str(source.get(ENV_VAR, "")).strip().lower() in _TRUE
