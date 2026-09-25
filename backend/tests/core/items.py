"""A feature-independent table for testing core query helpers."""

from sqlalchemy import Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class ItemBase(DeclarativeBase):
    pass


class Item(ItemBase):
    __tablename__ = "core_test_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(50))
    note: Mapped[str | None] = mapped_column(String(50))
    rank: Mapped[int] = mapped_column(Integer)


ITEMS = [
    Item(id=1, name="Alpha", note="first", rank=2),
    Item(id=2, name="beta", note="100% sure", rank=1),
    Item(id=3, name="Gamma", note="snake_case", rank=2),
    Item(id=4, name="delta", note=None, rank=3),
    Item(id=5, name="Epsilon", note="back\\slash", rank=1),
]
