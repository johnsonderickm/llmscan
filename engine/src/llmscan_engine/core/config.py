from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_prefix="LLMSCAN_",
        # Check both project root and engine/ directory for .env
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    target_url: Optional[str] = None
    api_key: Optional[str] = None
    max_concurrency: int = Field(default=3, ge=1, le=10)
    scan_profile: str = "standard"
    judge_api_key: Optional[str] = None
    judge_model: Optional[str] = None


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Return the cached Settings singleton."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
