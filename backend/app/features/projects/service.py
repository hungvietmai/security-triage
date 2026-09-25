"""Project persistence. Functions take a Session and never touch HTTP concerns."""

from typing import Any

from sqlalchemy import SQLColumnExpression, select
from sqlalchemy.orm import Session

from app.core.filtering import apply_search
from app.core.pagination import PageParams, PageResult, paginate
from app.core.sorting import Sort, apply_sort
from app.features.projects.models import Project
from app.features.projects.schemas import ProjectCreate

# API sort field -> column. The single source for which fields `?sort=` accepts.
SORT_COLUMNS: dict[str, SQLColumnExpression[Any]] = {
    "created_at": Project.created_at,
    "name": Project.name,
}


def create_project(session: Session, data: ProjectCreate) -> Project:
    project = Project(**data.model_dump())
    session.add(project)
    session.commit()
    session.refresh(project)
    return project


def list_projects(
    session: Session, *, page: PageParams, sort: Sort, search: str | None = None
) -> PageResult[Project]:
    statement = apply_search(select(Project), search, Project.name, Project.description)
    statement = apply_sort(statement, sort, SORT_COLUMNS, tiebreaker=Project.id)
    return paginate(session, statement, page)
