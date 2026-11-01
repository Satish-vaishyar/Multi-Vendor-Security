"""Backend facade for the shared secret-redaction rules (they live in okf/src/redact.py,
dependency-free so the OKF LLM gateway can use them too)."""
from __future__ import annotations
import importlib.util
from functools import lru_cache

from app.core import config as cfg


@lru_cache(maxsize=1)
def _mod():
    path = cfg.OKF_DIR / "src" / "redact.py"
    spec = importlib.util.spec_from_file_location("okf_redact", path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError(f"cannot load redaction rules from {path}")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def redact_secrets(text: str) -> str:
    return _mod().redact_secrets(text)


def redact_line(line):
    return _mod().redact_line(line)


def contains_secret(text: str) -> bool:
    return _mod().contains_secret(text)
