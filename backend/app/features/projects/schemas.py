import uuid
from datetime import datetime
from typing import Annotated

from pydantic import Field

from app.core.pagination import Page
from app.core.schemas import BlankToNone, InputSchema, ReadSchema
from app.features.projects.constants import PROJECT_DESCRIPTION_MAX, PROJECT_NAME_MAX


class ProjectCreate(InputSchema):
    name: str = Field(min_length=1, max_length=PROJECT_NAME_MAX)
    description: Annotated[str | None, Field(max_length=PROJECT_DESCRIPTION_MAX), BlankToNone] = (
        None
    )


class ProjectRead(ReadSchema):
    id: uuid.UUID
    name: str
    description: str | None
    created_at: datetime


class ProjectPage(Page[ProjectRead]):
    """One page of projects."""
