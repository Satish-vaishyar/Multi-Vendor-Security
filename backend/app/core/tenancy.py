"""Request-scoped tenant (organisation) context.

The auth dependency binds the caller's org here; the persistence layer reads
it and adds ``org_id = <current>`` to every query/insert, so one tenant can
never read or write another tenant's rows. Code that legitimately needs to look
across tenants (login by e-mail, CLI maintenance) must say so explicitly with
``unscoped()``.
"""
from __future__ import annotations
import functools
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator, Optional

from app.core import config as cfg

_org: ContextVar[Optional[str]] = ContextVar("org_id", default=None)
_unscoped: ContextVar[bool] = ContextVar("org_unscoped", default=False)


def current_org() -> str:
    """Org of the current request (defaults to the single built-in org outside a request)."""
    return _org.get() or cfg.DEFAULT_ORG_ID


def set_org(org_id: Optional[str]) -> None:
    _org.set(org_id)


def is_unscoped() -> bool:
    return _unscoped.get()


@contextmanager
def use_org(org_id: str) -> Iterator[None]:
    tok = _org.set(org_id)
    try:
        yield
    finally:
        _org.reset(tok)


@contextmanager
def unscoped() -> Iterator[None]:
    """Disable tenant filtering inside the block (explicit, greppable)."""
    tok = _unscoped.set(True)
    try:
        yield
    finally:
        _unscoped.reset(tok)


def system(fn):
    """Decorator: run ``fn`` in the explicit system scope (cross-tenant by design: worker queue operations, scheduler
    ticks, platform metrics, identity lookups). Visible and greppable, like ``unscoped()``."""
    @functools.wraps(fn)
    def wrapper(*a, **k):
        with unscoped():
            return fn(*a, **k)
    return wrapper
