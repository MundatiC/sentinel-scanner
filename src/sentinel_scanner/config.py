"""Settings come from environment variables (or a local .env file), never from CLI arguments."""

from __future__ import annotations

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_file=".env", extra="ignore")

    api_url: str = "http://localhost:4000"
    # SecretStr prints as '**********', so the key cannot leak into logs or tracebacks by accident.
    api_key: SecretStr | None = None
    request_delay: float = Field(default=0.5, ge=0, le=60)
    timeout: float = Field(default=10.0, gt=0, le=120)


def load_settings() -> Settings:
    return Settings()
