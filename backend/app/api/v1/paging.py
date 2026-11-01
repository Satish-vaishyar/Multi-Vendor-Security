"""Shared pagination / sorting / search query params for list endpoints.

Contract (all paged list endpoints): ?page=1&page_size=50&sort=<col>&order=asc|desc&q=<text>
Response data: {"items": [...], "total": <matching rows>, "page": n, "page_size": n}.
Sort columns are validated against a per-entity whitelist in core/persist.py;
anything else (including injection attempts) is rejected with HTTP 400.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import HTTPException, Query

from app.core import persist as db

MAX_PAGE_SIZE = db.MAX_PAGE_SIZE


@dataclass
class Pager:
    page: int = 1
    page_size: int = 50
    sort: Optional[str] = None
    order: str = "desc"
    q: Optional[str] = None


def pager(default_size: int = 50, default_order: str = "desc", max_size: int = MAX_PAGE_SIZE) -> Callable[..., Pager]:
    """Build a FastAPI dependency with an endpoint-specific default page size."""
    def _dep(page: int = Query(1, ge=1, le=1_000_000),
             page_size: int = Query(default_size, ge=1, le=max_size),
             sort: Optional[str] = Query(None, max_length=64),
             order: str = Query(default_order, pattern="^(?i:asc|desc)$"),
             q: Optional[str] = Query(None, max_length=100)) -> Pager:
        return Pager(page, page_size, sort, order, (q or "").strip() or None)
    return _dep


def paged(entity: str, p: Pager, columns: Optional[List[str]] = None, search: Tuple[str, ...] = (),
          default_sort: str = "created_at", **filters: Any) -> Tuple[List[Dict[str, Any]], int]:
    """db.select_page with ValueError -> HTTP 400."""
    try:
        return db.select_page(entity, columns, page=p.page, page_size=p.page_size, sort=p.sort,
                              order=p.order, q=p.q, search=search, default_sort=default_sort, **filters)
    except ValueError as e:
        raise HTTPException(400, str(e))


def envelope(items: list, total: int, p: Pager, **extra: Any) -> Dict[str, Any]:
    return {"items": items, "total": total, "page": p.page, "page_size": p.page_size, **extra}
