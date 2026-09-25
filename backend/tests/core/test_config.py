from pathlib import Path

from pydantic_settings import SettingsConfigDict

from app.core.config import ROOT_ENV_FILE, Settings


class EnvOnlySettings(Settings):
    """Reads environment variables only, so a developer's .env cannot leak in."""

    model_config = SettingsConfigDict(**{**Settings.model_config, "env_file": None})


def test_local_urls_follow_compose_variables(monkeypatch):
    for name in ["DATABASE_URL", "S3_ENDPOINT_URL"]:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("POSTGRES_PASSWORD", "p@ss/word")
    monkeypatch.setenv("POSTGRES_PORT", "15432")
    monkeypatch.setenv("S3_PORT", "18333")
    settings = EnvOnlySettings()
    assert settings.database_url == (
        "postgresql+psycopg://triage:p%40ss%2Fword@localhost:15432/triage"
    )
    assert settings.s3_endpoint_url == "http://localhost:18333"


def test_explicit_urls_take_precedence(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@db:5432/x")
    monkeypatch.setenv("S3_ENDPOINT_URL", "http://seaweedfs:8333")
    settings = EnvOnlySettings()
    assert settings.database_url == "postgresql+psycopg://u:p@db:5432/x"
    assert settings.s3_endpoint_url == "http://seaweedfs:8333"


def test_root_env_file_is_next_to_the_backend_project():
    # Guards against moving config.py without updating the parents[] depth.
    # In a checkout that is the repository root; in the Docker image, "/".
    backend_dir = Path(__file__).resolve().parents[2]
    assert (backend_dir / "pyproject.toml").is_file()
    assert ROOT_ENV_FILE == backend_dir.parent / ".env"
