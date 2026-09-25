import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.filtering import SEARCH_MAX_LENGTH, SearchQuery, apply_search, escape_like
from tests.core.items import Item


def ids(session, query: str | None) -> list[int]:
    statement = apply_search(select(Item), query, Item.name, Item.note).order_by(Item.id)
    return [item.id for item in session.scalars(statement)]


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("ALPHA", [1]),  # case-insensitive
        ("eta", [2]),  # substring
        ("first", [1]),  # second column
        ("a", [1, 2, 3, 4, 5]),
        (None, [1, 2, 3, 4, 5]),  # no filter
        ("   ", [1, 2, 3, 4, 5]),  # blank is no filter
        ("zzz", []),
    ],
)
def test_apply_search(item_session, query, expected):
    assert ids(item_session, query) == expected


@pytest.mark.parametrize(
    ("query", "expected"),
    [("100%", [2]), ("%", [2]), ("_", [3]), ("\\", [5])],
)
def test_wildcards_are_matched_literally(item_session, query, expected):
    assert ids(item_session, query) == expected


def test_escape_like():
    assert escape_like("a%b_c\\d") == "a\\%b\\_c\\\\d"


def test_apply_search_requires_columns():
    with pytest.raises(ValueError, match="at least one column"):
        apply_search(select(Item), "x")


def test_search_query_parameter_limits():
    app = FastAPI()

    @app.get("/")
    def endpoint(q: SearchQuery = None) -> dict[str, str | None]:
        return {"q": q}

    client = TestClient(app)
    assert client.get("/").json() == {"q": None}
    assert client.get("/?q=abc").json() == {"q": "abc"}
    assert client.get("/?q=").status_code == 422
    assert client.get("/", params={"q": "x" * (SEARCH_MAX_LENGTH + 1)}).status_code == 422
