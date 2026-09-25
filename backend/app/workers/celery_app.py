from celery import Celery
from celery.signals import after_setup_logger

from app.core.config import get_settings
from app.core.logging import configure_logging

celery_app = Celery("security_triage", broker=get_settings().redis_url)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_ignore_result=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    timezone="UTC",
)


# after_setup_logger adds our `app` logger config on top of Celery's own.
# (Connecting to setup_logging instead would disable Celery's logging entirely.)
@after_setup_logger.connect
def _configure_logging(**_: object) -> None:
    configure_logging()


@celery_app.task(name="triage.ping")
def ping() -> str:
    """Smoke task only; scan results will be persisted in PostgreSQL."""
    return "pong"
