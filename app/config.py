"""Application configuration.

Settings are read from environment variables (or a local ``.env`` file) so that
no secret is hard-coded in the source tree. Sensible development defaults are
provided to keep the project runnable out of the box.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "RBAC College Portal"

    # Database
    database_url: str = "sqlite:///./portal.db"

    # Session / JWT
    secret_key: str = "dev-only-insecure-secret-change-me"
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 30

    # Login hardening
    max_failed_logins: int = 5
    lockout_window_minutes: int = 15

    # Cookie used by the browser portal (the JSON API may use a Bearer token)
    session_cookie_name: str = "portal_session"
    cookie_secure: bool = False  # True behind HTTPS in a real deployment


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
