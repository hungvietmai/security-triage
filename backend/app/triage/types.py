"""Shared typed records for sink location and reconciliation."""

from __future__ import annotations

from typing import NotRequired, TypedDict


class Span(TypedDict):
    startLine: int
    startColumn: int
    endLine: int
    endColumn: int


class SinkArgument(TypedDict):
    position: int | None
    keyword: str | None
    span: Span
    text: str
    value_kind: str
    literal_bool: bool | None
    sequence_items: NotRequired[list[Span]]


class SinkRecord(TypedDict):
    path: str
    span: Span
    callee: str
    sink_kind: str
    args: list[SinkArgument]
