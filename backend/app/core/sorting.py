"""`?sort=field` / `?sort=-field` query parameter restricted to declared fields.

Usage in a feature:

    # service.py — map API field names to columns; the API never sees column names.
    SORT_COLUMNS = {"name": Thing.name, "created_at": Thing.created_at}
    statement = apply_sort(select(Thing), sort, SORT_COLUMNS, tiebreaker=Thing.id)

    # dependencies.py
    ThingSortDep = Annotated[Sort, Depends(sort_param(SORT_COLUMNS, default="-created_at"))]
"""

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Query
from sqlalchemy import Select, SQLColumnExpression


@dataclass(frozen=True, slots=True)
class Sort:
    field: str
    descending: bool = False

    @classmethod
    def parse(cls, value: str) -> "Sort":
        return cls(field=value.removeprefix("-"), descending=value.startswith("-"))


def sort_param(fields: Iterable[str], *, default: str) -> Callable[..., Sort]:
    """Build a dependency accepting `field` or `-field` for each allowed field.

    Unknown fields fail validation (422) and the pattern is documented in OpenAPI.
    """
    names = sorted(fields)
    if default.removeprefix("-") not in names:
        raise ValueError(f"default sort {default!r} is not one of {names}")
    pattern = rf"^-?({'|'.join(map(re.escape, names))})$"
    description = (
        f"Sort field, prefixed with '-' for descending. One of: {', '.join(names)}. "
        f"Default: {default}."
    )

    def dependency(
        sort: Annotated[str, Query(pattern=pattern, description=description)] = default,
    ) -> Sort:
        return Sort.parse(sort)

    return dependency


def apply_sort[S: Select[Any]](
    statement: S,
    sort: Sort,
    columns: Mapping[str, SQLColumnExpression[Any]],
    *,
    tiebreaker: SQLColumnExpression[Any],
) -> S:
    """Order by the requested column, then by a unique `tiebreaker` so that
    pagination is deterministic when sort values repeat."""
    column = columns[sort.field]
    return statement.order_by(column.desc() if sort.descending else column.asc(), tiebreaker)
