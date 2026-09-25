from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_session
from app.models import Project
from app.schemas import ProjectCreate, ProjectPage, ProjectRead

router = APIRouter(prefix="/projects", tags=["projects"])
Database = Annotated[Session, Depends(get_session)]


@router.post("", response_model=ProjectRead, status_code=201)
def create_project(payload: ProjectCreate, session: Database) -> Project:
    project = Project(**payload.model_dump())
    session.add(project)
    session.commit()
    session.refresh(project)
    return project


@router.get("", response_model=ProjectPage)
def list_projects(
    session: Database,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ProjectPage:
    projects = session.scalars(
        select(Project).order_by(Project.created_at.desc(), Project.id).limit(limit).offset(offset)
    ).all()
    total = session.scalar(select(func.count()).select_from(Project)) or 0
    return ProjectPage(
        items=[ProjectRead.model_validate(project) for project in projects],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{project_id}", response_model=ProjectRead)
def get_project(project_id: UUID, session: Database) -> Project:
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project
