from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from app.core.pagination import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    Page,
    PageParams,
    PageParamsDep,
    PageResult,
    paginate,
)
from tests.core.items import Item


class ItemRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str


class ItemPage(Page[ItemRead]):
    pass


def test_paginate_slices_and_counts_all_matches(item_session):
    statement = select(Item).order_by(Item.id)
    result = paginate(item_session, statement, PageParams(limit=2, offset=2))
    assert [item.id for item in result.items] == [3, 4]
    assert (result.total, result.limit, result.offset) == (5, 2, 2)


def test_paginate_counts_filtered_rows_and_handles_empty_pages(item_session):
    statement = select(Item).where(Item.rank == 2).order_by(Item.id)
    assert paginate(item_session, statement, PageParams(limit=10)).total == 2
    past_end = paginate(item_session, statement, PageParams(limit=10, offset=50))
    assert (list(past_end.items), past_end.total) == ([], 2)


def test_page_schema_validates_orm_items(item_session):
    result = paginate(item_session, select(Item).order_by(Item.id), PageParams(limit=1))
    page = ItemPage.from_result(result)
    assert page.model_dump() == {
        "items": [{"id": 1, "name": "Alpha"}],
        "total": 5,
        "limit": 1,
        "offset": 0,
    }
    # Subclassing gives the OpenAPI schema a stable name.
    assert ItemPage.model_json_schema()["title"] == "ItemPage"


def test_page_result_is_generic_over_any_item():
    result = PageResult(items=["a"], total=1, limit=1, offset=0)
    assert result.items == ["a"]


def test_page_params_dependency_validates_and_defaults():
    app = FastAPI()

    @app.get("/")
    def endpoint(page: PageParamsDep) -> dict[str, int]:
        return {"limit": page.limit, "offset": page.offset}

    client = TestClient(app)
    assert client.get("/").json() == {"limit": DEFAULT_LIMIT, "offset": 0}
    assert client.get("/?limit=5&offset=10").json() == {"limit": 5, "offset": 10}
    for bad in ["limit=0", f"limit={MAX_LIMIT + 1}", "offset=-1", "limit=x"]:
        assert client.get(f"/?{bad}").status_code == 422, bad
