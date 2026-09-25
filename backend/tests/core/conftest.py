"""Fixtures backed by the feature-independent table in tests/core/items.py."""

from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from tests.core.items import ITEMS, Item, ItemBase


@pytest.fixture
def item_engine() -> Iterator[Engine]:
    engine = create_engine("sqlite://", poolclass=StaticPool)
    ItemBase.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all(Item(id=i.id, name=i.name, note=i.note, rank=i.rank) for i in ITEMS)
        session.commit()
    yield engine
    engine.dispose()


@pytest.fixture
def item_session(item_engine: Engine) -> Iterator[Session]:
    with Session(item_engine) as session:
        yield session
