from typing import Annotated

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.sorting import Sort, apply_sort, sort_param
from tests.core.items import Item

COLUMNS = {"name": Item.name, "rank": Item.rank}
SortDep = Annotated[Sort, Depends(sort_param(COLUMNS, default="-rank"))]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("name", Sort("name", descending=False)), ("-rank", Sort("rank", descending=True))],
)
def test_parse(raw, expected):
    assert Sort.parse(raw) == expected


def test_apply_sort_breaks_ties_with_the_tiebreaker(item_session):
    ascending = apply_sort(select(Item), Sort("rank"), COLUMNS, tiebreaker=Item.id)
    assert [i.id for i in item_session.scalars(ascending)] == [2, 5, 1, 3, 4]
    descending = apply_sort(select(Item), Sort("rank", True), COLUMNS, tiebreaker=Item.id)
    assert [i.id for i in item_session.scalars(descending)] == [4, 1, 3, 2, 5]


def test_sort_param_accepts_declared_fields_only():
    app = FastAPI()

    @app.get("/")
    def endpoint(sort: SortDep) -> dict[str, object]:
        return {"field": sort.field, "descending": sort.descending}

    client = TestClient(app)
    assert client.get("/").json() == {"field": "rank", "descending": True}
    assert client.get("/?sort=name").json() == {"field": "name", "descending": False}
    for bad in ["id", "-note", "name;drop", "--name", ""]:
        assert client.get("/", params={"sort": bad}).status_code == 422, bad

    parameter = app.openapi()["paths"]["/"]["get"]["parameters"][0]
    assert parameter["schema"]["pattern"] == "^-?(name|rank)$"
    assert parameter["schema"]["default"] == "-rank"


def test_sort_param_rejects_an_undeclared_default():
    with pytest.raises(ValueError, match="default sort"):
        sort_param(COLUMNS, default="-id")
