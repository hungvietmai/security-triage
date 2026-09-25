from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import quote

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Repository-root .env shared with Docker Compose (this file is app/core/config.py);
# a .env in the working directory takes precedence.
ROOT_ENV_FILE = Path(__file__).resolve().parents[3] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(ROOT_ENV_FILE, ".env"), extra="ignore")

    # Compose-level variables, used to derive localhost URLs when running outside Docker.
    postgres_password: SecretStr = SecretStr("triage_dev")
    postgres_port: int = 5432
    s3_port: int = 8333

    database_url: str = ""
    redis_url: str = "redis://localhost:6379/0"
    s3_endpoint_url: str = ""
    s3_access_key: str = "triage-local"
    s3_secret_key: SecretStr = SecretStr("triage-local-development-only")
    s3_bucket: str = "source-artifacts"
    s3_region: str = "us-east-1"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @model_validator(mode="after")
    def derive_local_urls(self) -> "Settings":
        if not self.database_url:
            password = quote(self.postgres_password.get_secret_value(), safe="")
            self.database_url = (
                f"postgresql+psycopg://triage:{password}@localhost:{self.postgres_port}/triage"
            )
        if not self.s3_endpoint_url:
            self.s3_endpoint_url = f"http://localhost:{self.s3_port}"
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
