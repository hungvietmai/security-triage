"""Free-text search: the `?q=` query parameter and a case-insensitive filter helper.

Usage in a feature:

    # router.py
    def list_things(..., q: SearchQuery = None): ...

    # service.py
    statement = apply_search(select(Thing), q, Thing.name, Thing.description)
"""

from typing import Annotated, Any

from fastapi import Query
from sqlalchemy import Select, SQLColumnExpression, or_

SEARCH_MAX_LENGTH = 100

SearchQuery = Annotated[
    str | None,
    Query(
        min_length=1,
        max_length=SEARCH_MAX_LENGTH,
        description="Case-insensitive substring match",
    ),
]

_ESCAPE = "\\"


def escape_like(value: str) -> str:
    """Treat %, _ and the escape character literally inside a LIKE pattern."""
    return (
        value.replace(_ESCAPE, _ESCAPE * 2).replace("%", f"{_ESCAPE}%").replace("_", f"{_ESCAPE}_")
    )


def apply_search[S: Select[Any]](
    statement: S, query: str | None, *columns: SQLColumnExpression[Any]
) -> S:
    """Keep rows where any of `columns` contains `query` (ignoring case).

    A missing or whitespace-only query leaves the statement unchanged.
    """
    if not columns:
        raise ValueError("apply_search needs at least one column")
    term = (query or "").strip()
    if not term:
        return statement
    pattern = f"%{escape_like(term)}%"
    return statement.where(or_(*(column.ilike(pattern, escape=_ESCAPE) for column in columns)))
