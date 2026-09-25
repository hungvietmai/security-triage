from unittest.mock import MagicMock

from app.api import health


def test_liveness_does_not_require_storage(client):
    assert client.get("/api/v1/health/live").json() == {"status": "ok"}


def test_readiness_distinguishes_storage_failure(client, monkeypatch):
    redis = MagicMock()
    monkeypatch.setattr(health.Redis, "from_url", redis)
    storage = MagicMock()
    storage.return_value.head_bucket.side_effect = OSError("Unavailable")
    monkeypatch.setattr(health, "get_s3_client", storage)
    response = client.get("/api/v1/health/ready")
    assert response.status_code == 503
    assert response.json()["checks"] == {"postgres": "ok", "redis": "ok", "storage": "unavailable"}


def test_readiness_success(client, monkeypatch):
    monkeypatch.setattr(health.Redis, "from_url", MagicMock())
    monkeypatch.setattr(health, "get_s3_client", MagicMock())
    response = client.get("/api/v1/health/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
