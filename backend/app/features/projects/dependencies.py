import uuid
from typing import Annotated

from fastapi import Depends

from app.core.database import SessionDep, get_or_raise
from app.core.sorting import Sort, sort_param
from app.features.projects import service
from app.features.projects.constants import PROJECT_DEFAULT_SORT
from app.features.projects.exceptions import ProjectNotFound
from app.features.projects.models import Project


def valid_project_id(project_id: uuid.UUID, session: SessionDep) -> Project:
    """Resolve the `project_id` path parameter or answer 404."""
    return get_or_raise(session, Project, project_id, ProjectNotFound)


ProjectDep = Annotated[Project, Depends(valid_project_id)]

ProjectSortDep = Annotated[
    Sort, Depends(sort_param(service.SORT_COLUMNS, default=PROJECT_DEFAULT_SORT))
]
