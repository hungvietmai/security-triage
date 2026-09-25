from unittest.mock import MagicMock

import pytest
from redis import Redis
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import Base
from app.features.health import service


@pytest.fixture
def healthy_externals(monkeypatch):
    """Redis and S3 answer; PostgreSQL is the real test database."""
    monkeypatch.setattr(Redis, "from_url", MagicMock())
    monkeypatch.setattr(service, "get_s3_client", MagicMock())


def test_liveness_does_not_require_dependencies(client):
    assert client.get("/api/v1/health/live").json() == {"status": "ok"}


def test_readiness_success(client, healthy_externals):
    response = client.get("/api/v1/health/ready")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "checks": {"postgres": "ok", "redis": "ok", "storage": "ok"},
    }


def test_readiness_distinguishes_storage_failure(client, monkeypatch):
    monkeypatch.setattr(Redis, "from_url", MagicMock())
    storage = MagicMock()
    storage.return_value.head_bucket.side_effect = OSError("Unavailable")
    monkeypatch.setattr(service, "get_s3_client", storage)
    response = client.get("/api/v1/health/ready")
    assert response.status_code == 503
    assert response.json() == {
        "status": "degraded",
        "checks": {"postgres": "ok", "redis": "ok", "storage": "unavailable"},
    }


def test_readiness_reports_redis_failure(client, healthy_externals, monkeypatch):
    monkeypatch.setattr(Redis, "from_url", MagicMock(side_effect=ConnectionError("refused")))
    response = client.get("/api/v1/health/ready")
    assert response.status_code == 503
    assert response.json()["checks"]["redis"] == "unavailable"


def test_postgres_check_fails_without_schema_and_leaves_session_usable(engine):
    # A database that is reachable but not migrated must not count as ready.
    Base.metadata.drop_all(engine)
    with Session(engine) as session:
        assert service.check_postgres(session) == "unavailable"
        # The failed statement was rolled back, so the session still works.
        assert session.execute(text("SELECT 1")).scalar_one() == 1
