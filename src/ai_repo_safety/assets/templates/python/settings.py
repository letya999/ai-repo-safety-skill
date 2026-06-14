from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Safe settings example.

    Keep real secrets outside Git. Commit only `.env.example`.
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = "sqlite:///local.db"
    api_key: str = "replace_me"
    secret_key: str = "replace_me"


def get_settings() -> Settings:
    return Settings()
