"""
Module: config
Purpose: Centralized application configuration using Pydantic Settings for environment-driven
         configuration. Provides safe defaults for local development while avoiding hardcoded secrets.

Security: Never log or expose secret values. This module only reads environment variables.
"""

from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings


class AppSettings(BaseSettings):
    """
    Application settings loaded from environment variables.

    Attributes:
        database_url: SQLAlchemy database URL. Defaults to SQLite file for local dev.
        secret_key: Secret key used for signing tokens (e.g., JWT). Must be provided in prod.
        access_token_expire_minutes: JWT access token expiry time in minutes.
        environment: Current environment (development/staging/production).
        cors_allow_origins: Comma-separated origins allowed by CORS.
    """

    database_url: str = Field(
        default="sqlite:///./app.db",
        alias="DATABASE_URL",
        description="Full SQLAlchemy DB URL; defaults to local SQLite file.",
    )
    secret_key: str = Field(
        default="CHANGE_ME_IN_PRODUCTION",
        alias="SECRET_KEY",
        description="Secret key for signing tokens. MUST be overridden in production.",
    )
    access_token_expire_minutes: int = Field(
        default=60,
        alias="ACCESS_TOKEN_EXPIRE_MINUTES",
        description="Access token expiry time in minutes.",
    )
    environment: str = Field(
        default="development",
        alias="ENVIRONMENT",
        description="Application environment: development/staging/production.",
    )
    cors_allow_origins: str = Field(
        default="*",
        alias="CORS_ALLOW_ORIGINS",
        description="Comma-separated list of allowed CORS origins.",
    )

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
        "case_sensitive": False,
    }


# PUBLIC_INTERFACE
def get_settings() -> AppSettings:
    """Return a cached instance of application settings loaded from environment."""
    return _get_cached_settings()


@lru_cache(maxsize=1)
def _get_cached_settings() -> AppSettings:
    """
    Internal cached loader for settings to avoid repeated file reads and parsing.
    """
    return AppSettings()
