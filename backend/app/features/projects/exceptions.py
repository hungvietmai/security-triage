from app.core.exceptions import NotFoundError


class ProjectNotFound(NotFoundError):
    detail = "Project not found"
