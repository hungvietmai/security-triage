from typing import Annotated

import pytest
from pydantic import Field, ValidationError

from app.core.schemas import BlankToNone, InputSchema, ReadSchema


class Note(InputSchema):
    title: str = Field(min_length=1)
    body: Annotated[str | None, Field(max_length=5), BlankToNone] = None


@pytest.mark.parametrize(
    ("body", "expected"),
    [(None, None), ("", None), ("   ", None), (" ab ", "ab"), ("abcde", "abcde")],
)
def test_blank_to_none_after_stripping(body, expected):
    assert Note(title="t", body=body).body == expected


@pytest.mark.parametrize("body", ["abcdef", 3])
def test_constraints_still_apply(body):
    # Regression: with BlankToNone placed before the constraint, None and blank
    # input crashed with TypeError (a 500) instead of validating.
    with pytest.raises(ValidationError):
        Note(title="t", body=body)


def test_input_schema_strips_and_forbids_unknown_fields():
    assert Note(title="  t  ").title == "t"
    with pytest.raises(ValidationError, match="extra_forbidden"):
        Note.model_validate({"title": "t", "id": 1})


def test_blank_to_none_keeps_a_clean_openapi_schema():
    assert Note.model_json_schema()["properties"]["body"]["anyOf"] == [
        {"maxLength": 5, "type": "string"},
        {"type": "null"},
    ]


def test_read_schema_reads_attributes():
    class ThingRead(ReadSchema):
        name: str

    class Thing:
        name = "orm object"

    assert ThingRead.model_validate(Thing()).name == "orm object"
