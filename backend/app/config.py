from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://triage:triage_dev@localhost:5432/triage"
    redis_url: str = "redis://localhost:6379/0"
    s3_endpoint_url: str = "http://localhost:8333"
    s3_access_key: str = "triage-local"
    s3_secret_key: SecretStr = SecretStr("triage-local-development-only")
    s3_bucket: str = "source-artifacts"
    s3_region: str = "us-east-1"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
