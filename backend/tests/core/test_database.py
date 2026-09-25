import pytest

from app.core.database import get_or_raise
from app.core.exceptions import NotFoundError
from tests.core.items import Item


class ItemNotFound(NotFoundError):
    detail = "Item not found"


def test_get_or_raise_returns_the_instance(item_session):
    assert get_or_raise(item_session, Item, 3).name == "Gamma"


def test_get_or_raise_raises_the_feature_error(item_session):
    with pytest.raises(ItemNotFound, match="Item not found"):
        get_or_raise(item_session, Item, 999, ItemNotFound)


def test_get_or_raise_defaults_to_not_found(item_session):
    with pytest.raises(NotFoundError, match="Not found"):
        get_or_raise(item_session, Item, 999)
