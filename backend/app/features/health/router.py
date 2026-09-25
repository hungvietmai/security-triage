from fastapi import APIRouter, Response, status

from app.core.database import SessionDep
from app.features.health import service
from app.features.health.schemas import Liveness, Readiness

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live")
def liveness() -> Liveness:
    return Liveness()


@router.get(
    "/ready",
    responses={503: {"model": Readiness, "description": "A dependency is unavailable"}},
)
def readiness(session: SessionDep, response: Response) -> Readiness:
    result = service.readiness(session)
    if result.status != "ok":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return result
