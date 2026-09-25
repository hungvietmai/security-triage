import logging
from contextlib import closing
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from redis import Redis
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_session
from app.services.storage import get_s3_client

router = APIRouter(prefix="/health", tags=["health"])
logger = logging.getLogger(__name__)


@router.get("/live")
def liveness() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
def readiness(session: Annotated[Session, Depends(get_session)]) -> JSONResponse:
    settings = get_settings()
    checks: dict[str, str] = {}
    try:
        session.execute(text("SELECT id FROM projects LIMIT 0"))
        checks["postgres"] = "ok"
    except Exception:
        session.rollback()
        logger.exception("PostgreSQL readiness failed")
        checks["postgres"] = "unavailable"
    try:
        with Redis.from_url(
            settings.redis_url, socket_connect_timeout=2, socket_timeout=2
        ) as redis:
            redis.ping()
        checks["redis"] = "ok"
    except Exception:
        logger.exception("Redis readiness failed")
        checks["redis"] = "unavailable"
    try:
        with closing(get_s3_client()) as client:
            client.head_bucket(Bucket=settings.s3_bucket)
        checks["storage"] = "ok"
    except Exception:
        logger.exception("S3 readiness failed")
        checks["storage"] = "unavailable"
    ready = all(value == "ok" for value in checks.values())
    return JSONResponse(
        status_code=200 if ready else 503,
        content={"status": "ok" if ready else "degraded", "checks": checks},
    )
