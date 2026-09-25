"""Offset pagination: query parameters, a generic page schema and the query helper.

Usage in a feature:

    # service.py
    def list_things(session, *, page: PageParams) -> PageResult[Thing]:
        return paginate(session, select(Thing).order_by(...), page)

    # schemas.py
    class ThingPage(Page[ThingRead]): ...

    # router.py
    @router.get("", response_model=ThingPage)
    def list_things(session: SessionDep, page: PageParamsDep) -> ThingPage:
        return ThingPage.from_result(service.list_things(session, page=page))
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Annotated, Any, Self

from fastapi import Depends, Query
from pydantic import BaseModel
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

DEFAULT_LIMIT = 20
MAX_LIMIT = 100


@dataclass(frozen=True, slots=True)
class PageParams:
    limit: int = DEFAULT_LIMIT
    offset: int = 0


def page_params(
    limit: Annotated[
        int, Query(ge=1, le=MAX_LIMIT, description="Maximum number of items to return")
    ] = DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0, description="Number of items to skip")] = 0,
) -> PageParams:
    return PageParams(limit=limit, offset=offset)


PageParamsDep = Annotated[PageParams, Depends(page_params)]


@dataclass(frozen=True, slots=True)
class PageResult[T]:
    """One page of ORM objects, as returned by services."""

    items: Sequence[T]
    total: int
    limit: int
    offset: int


class Page[ItemT](BaseModel):
    """Response envelope. Subclass per resource (`class ProjectPage(Page[ProjectRead])`)
    so the OpenAPI schema gets a stable, readable name."""

    items: list[ItemT]
    total: int
    limit: int
    offset: int

    @classmethod
    def from_result(cls, result: PageResult[Any]) -> Self:
        # from_attributes lets ORM items validate into the item schema.
        return cls.model_validate(result, from_attributes=True)


def paginate[T](session: Session, statement: Select[T], params: PageParams) -> PageResult[T]:
    """Run `statement` for one page and count all matching rows.

    The statement must be fully ordered (see `core.sorting`), or rows may repeat
    or disappear between pages.
    """
    total = session.scalar(select(func.count()).select_from(statement.order_by(None).subquery()))
    items = session.scalars(statement.limit(params.limit).offset(params.offset)).all()
    return PageResult(items=items, total=total or 0, limit=params.limit, offset=params.offset)
