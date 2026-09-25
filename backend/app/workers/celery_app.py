from celery import Celery

from app.config import get_settings

celery_app = Celery("security_triage", broker=get_settings().redis_url)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_ignore_result=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    timezone="UTC",
)


@celery_app.task(name="triage.ping")
def ping() -> str:
    """Smoke task only; scan results will be persisted in PostgreSQL."""
    return "pong"
