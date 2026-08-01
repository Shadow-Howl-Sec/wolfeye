"""
WolfEye — Configuration Classes
=================================
Three configs share a common base:

* DevelopmentConfig  — SQLite, debug on, no rate-limit headaches
* ProductionConfig   — PostgreSQL (Supabase), secure defaults
* TestingConfig      — in-memory SQLite, scheduler off
"""

from __future__ import annotations

import os
from pathlib import Path

# Project root (one level above this file)
BASE_DIR = Path(__file__).resolve().parent.parent


class BaseConfig:
    """Settings common to every environment."""

    # Flask
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-key-change-in-prod")
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"

    # SQLAlchemy
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    # Rate limiting (flask-limiter)
    RATELIMIT_DEFAULT: str = os.getenv("RATELIMIT_DEFAULT", "60") + " per minute"
    RATELIMIT_STORAGE_URL: str = "memory://"

    # Demo / admin account credentials (loaded from .env)
    DEMO_USERNAME: str = os.getenv("DEMO_USERNAME", "demo")
    DEMO_PASSWORD: str = os.getenv("DEMO_PASSWORD", "wolfeye-demo")
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "change-me-admin-password")

    # Threat Intel API keys
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    THREATFOX_API_KEY: str = os.getenv("THREATFOX_API_KEY", "")

    # Email alert settings
    SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: str = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    ALERT_EMAIL_TO: str = os.getenv("ALERT_EMAIL_TO", "")

    # Anomaly threshold — IOC scores above this generate an alert
    ANOMALY_ALERT_THRESHOLD: float = float(os.getenv("ANOMALY_ALERT_THRESHOLD", "0.6"))

    # Ingestion schedule (APScheduler cron-style)
    INGESTION_INTERVAL_MINUTES: int = int(os.getenv("INGESTION_INTERVAL_MINUTES", "60"))


class DevelopmentConfig(BaseConfig):
    """Local development — SQLite, debug on."""

    DEBUG: bool = True
    SQLALCHEMY_DATABASE_URI: str = (
        os.getenv("DATABASE_URL")
        or f"sqlite:///{BASE_DIR / 'instance' / 'wolfeye_dev.db'}"
    )


class ProductionConfig(BaseConfig):
    """Render + Supabase deployment."""

    DEBUG: bool = False
    TESTING: bool = False
    SESSION_COOKIE_SECURE: bool = True  # HTTPS only

    SQLALCHEMY_DATABASE_URI: str = os.getenv("DATABASE_URL", "")

    # Supabase PostgreSQL connection strings start with postgres://
    # SQLAlchemy 2.x requires postgresql://
    @classmethod
    def _fix_db_url(cls) -> None:
        url = os.getenv("DATABASE_URL", "")
        if url.startswith("postgres://"):
            cls.SQLALCHEMY_DATABASE_URI = url.replace("postgres://", "postgresql://", 1)

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        cls._fix_db_url()


ProductionConfig._fix_db_url()  # also run for the class itself


class TestingConfig(BaseConfig):
    """Unit tests — in-memory SQLite, no scheduler."""

    TESTING: bool = True
    DEBUG: bool = True
    SQLALCHEMY_DATABASE_URI: str = "sqlite:///:memory:"
    WTF_CSRF_ENABLED: bool = False
    RATELIMIT_ENABLED: bool = False


# ---------------------------------------------------------------------------
# Registry used by create_app()
# ---------------------------------------------------------------------------

config_map: dict[str, type[BaseConfig]] = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}
