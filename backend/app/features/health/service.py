"""Dependency probes. Each returns a state and logs the cause instead of raising."""

import logging

from redis import Redis
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.storage import get_s3_client
from app.features.health.schemas import Readiness, ReadinessChecks, ServiceState

logger = logging.getLogger(__name__)


def check_postgres(session: Session) -> ServiceState:
    # Querying a migrated table also catches a database without the schema.
    try:
        session.execute(text("SELECT id FROM projects LIMIT 0"))
    except Exception:
        session.rollback()
        logger.exception("PostgreSQL readiness failed")
        return "unavailable"
    return "ok"


def check_redis() -> ServiceState:
    try:
        with Redis.from_url(
            get_settings().redis_url, socket_connect_timeout=2, socket_timeout=2
        ) as redis:
            redis.ping()
    except Exception:
        logger.exception("Redis readiness failed")
        return "unavailable"
    return "ok"


def check_storage() -> ServiceState:
    try:
        get_s3_client().head_bucket(Bucket=get_settings().s3_bucket)
    except Exception:
        logger.exception("S3 readiness failed")
        return "unavailable"
    return "ok"


def readiness(session: Session) -> Readiness:
    checks = ReadinessChecks(
        postgres=check_postgres(session), redis=check_redis(), storage=check_storage()
    )
    ready = all(state == "ok" for state in checks.model_dump().values())
    return Readiness(status="ok" if ready else "degraded", checks=checks)
