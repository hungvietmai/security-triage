from fastapi import APIRouter, status

from app.core.database import SessionDep
from app.core.exceptions import ErrorResponse
from app.core.filtering import SearchQuery
from app.core.pagination import PageParamsDep
from app.features.projects import service
from app.features.projects.dependencies import ProjectDep, ProjectSortDep
from app.features.projects.models import Project
from app.features.projects.schemas import ProjectCreate, ProjectPage, ProjectRead

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=ProjectRead, status_code=status.HTTP_201_CREATED)
def create_project(payload: ProjectCreate, session: SessionDep) -> Project:
    return service.create_project(session, payload)


@router.get("", response_model=ProjectPage)
def list_projects(
    session: SessionDep, page: PageParamsDep, sort: ProjectSortDep, q: SearchQuery = None
) -> ProjectPage:
    """Newest first by default; `q` matches name or description."""
    return ProjectPage.from_result(service.list_projects(session, page=page, sort=sort, search=q))


@router.get(
    "/{project_id}",
    response_model=ProjectRead,
    responses={404: {"model": ErrorResponse, "description": "Project not found"}},
)
def get_project(project: ProjectDep) -> Project:
    return project
