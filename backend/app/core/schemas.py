"""Base schemas and reusable field metadata for every feature's API models."""

from pydantic import AfterValidator, BaseModel, ConfigDict


class InputSchema(BaseModel):
    """Request bodies: strip surrounding whitespace, reject unknown fields."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")


class ReadSchema(BaseModel):
    """Responses built from ORM objects."""

    model_config = ConfigDict(from_attributes=True)


def _blank_to_none(value: str | None) -> str | None:
    return value or None


# Optional free text stored as NULL when blank ("" or, after stripping, "   ").
# Put it LAST, after any constraints:
#     description: Annotated[str | None, Field(max_length=4000), BlankToNone] = None
# Placed before a constraint, pydantic would apply max_length to None and crash (500).
BlankToNone = AfterValidator(_blank_to_none)
