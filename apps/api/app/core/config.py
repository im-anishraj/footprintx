"""FootprintX API — core configuration."""
from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ── Application ──────────────────────────────────────────────
    app_env: Literal["development", "production", "test"] = "development"
    web_origin: str = "http://localhost:3000"

    # ── Database ─────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://footprintx:footprintx@localhost:5432/footprintx"

    # ── Redis ────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Security ─────────────────────────────────────────────────
    server_pepper: str = Field(default_factory=lambda: secrets.token_hex(32))
    master_key: str = Field(default_factory=lambda: secrets.token_hex(32))
    session_secret: str = Field(default_factory=lambda: secrets.token_hex(32))
    scanner_queue_key: str = Field(default_factory=lambda: secrets.token_hex(32))

    # ── Scanner ──────────────────────────────────────────────────
    scanner_mode: Literal["mock", "live"] = "mock"
    scanner_concurrency: int = 8
    scanner_module_timeout: int = 10
    scanner_global_timeout: int = 60

    # ── HIBP ─────────────────────────────────────────────────────
    hibp_api_key: str = ""

    # ── Turnstile ────────────────────────────────────────────────
    turnstile_site_key: str = "1x00000000000000000000AA"
    turnstile_secret_key: str = "1x0000000000000000000000000000000AA"

    # ── Email ────────────────────────────────────────────────────
    email_provider: Literal["smtp", "resend"] = "smtp"
    resend_api_key: str = ""
    smtp_host: str = "localhost"
    smtp_port: int = 1025
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = False
    email_from: str = "verify@footprintx.local"

    # ── Sentry ───────────────────────────────────────────────────
    sentry_dsn: str = ""

    # ── Consent ──────────────────────────────────────────────────
    consent_version: str = "1.0.0"

    # ── Canary ───────────────────────────────────────────────────
    canary_config: str = ""

    # ── Paths ────────────────────────────────────────────────────
    project_root: Path = Path(__file__).resolve().parent.parent.parent.parent

    model_config = {"env_file": ".env", "extra": "ignore"}

    @property
    def is_dev(self) -> bool:
        return self.app_env == "development"

    @property
    def is_prod(self) -> bool:
        return self.app_env == "production"

    @property
    def is_test(self) -> bool:
        return self.app_env == "test"


@lru_cache
def get_settings() -> Settings:
    return Settings()
