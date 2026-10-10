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
    ANALYST_USERNAME: str = os.getenv("ANALYST_USERNAME", "analyst")
    ANALYST_PASSWORD: str = os.getenv("ANALYST_PASSWORD", "wolfeye-analyst")
    ADMIN_USERNAME: str = os.getenv("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD: str = os.getenv("ADMIN_PASSWORD", "change-me-admin-password")

    # Threat Intel API keys
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    THREATFOX_API_KEY: str = os.getenv("THREATFOX_API_KEY", "")
    LOCAL_INGEST_TOKEN: str = os.getenv("LOCAL_INGEST_TOKEN", "")
    MISP_URL: str = os.getenv("MISP_URL", "")
    MISP_KEY: str = os.getenv("MISP_KEY", "")
    MISP_VERIFY_SSL: bool = os.getenv("MISP_VERIFY_SSL", "true").lower() == "true"
    OPENCTI_URL: str = os.getenv("OPENCTI_URL", "")
    OPENCTI_TOKEN: str = os.getenv("OPENCTI_TOKEN", "")

    # Email alert settings
    SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER: str = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    ALERT_EMAIL_TO: str = os.getenv("ALERT_EMAIL_TO", "")

    # Risk threshold — IOC risk scores above this generate an alert.
    # Keep legacy env var support for older deployments.
    ALERT_MIN_SCORE: float = float(os.getenv("ALERT_MIN_SCORE", os.getenv("ANOMALY_ALERT_THRESHOLD", "0.6")))
    ANOMALY_ALERT_THRESHOLD: float = ALERT_MIN_SCORE

    ALERT_SEVERITY_BANDS: dict[str, float] = {
        "low": float(os.getenv("ALERT_SEVERITY_LOW", "0.60")),
        "medium": float(os.getenv("ALERT_SEVERITY_MEDIUM", "0.70")),
        "high": float(os.getenv("ALERT_SEVERITY_HIGH", "0.80")),
        "critical": float(os.getenv("ALERT_SEVERITY_CRITICAL", "0.90")),
    }

    # Control-plane / data-plane enforcement configuration
    CONTROL_PLANE_URL: str = os.getenv("CONTROL_PLANE_URL", "")
    NODE_TOKEN: str = os.getenv("NODE_TOKEN", "")
    NODE_NAME: str = os.getenv("NODE_NAME", "default-node")
    NODE_MODE: str = os.getenv("NODE_MODE", "gateway")
    UPSTREAM_URLS: list[str] = [
        value.strip() for value in os.getenv("UPSTREAM_URLS", "http://127.0.0.1:5000").split(",") if value.strip()
    ]
    LISTEN_HOST: str = os.getenv("LISTEN_HOST", "0.0.0.0")
    LISTEN_PORT: int = int(os.getenv("LISTEN_PORT", "8080"))
    TLS_CERT_PATH: str = os.getenv("TLS_CERT_PATH", "")
    TLS_KEY_PATH: str = os.getenv("TLS_KEY_PATH", "")
    TRUSTED_PROXIES: list[str] = [
        value.strip() for value in os.getenv("TRUSTED_PROXIES", "127.0.0.1,::1").split(",") if value.strip()
    ]
    OWN_NETWORKS: list[str] = [
        value.strip() for value in os.getenv("OWN_NETWORKS", "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").split(",") if value.strip()
    ]
    FAIL_MODE: str = os.getenv("FAIL_MODE", "open")
    DRY_RUN: bool = os.getenv("DRY_RUN", "false").lower() == "true"
    BLOCKING_ENABLED: bool = os.getenv("BLOCKING_ENABLED", "true").lower() == "true"
    RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
    RATE_LIMIT_CONNECTIONS: int = int(os.getenv("RATE_LIMIT_CONNECTIONS", "50"))
    RATE_WINDOW_SECONDS: int = int(os.getenv("RATE_WINDOW_SECONDS", "10"))
    BLOCK_ESCALATION: list[int] = [10, 60, 1440]
    ENFORCEMENT_POLL_SECONDS: int = int(os.getenv("ENFORCEMENT_POLL_SECONDS", "5"))
    SHARE_AUTO_BLOCKS: bool = os.getenv("SHARE_AUTO_BLOCKS", "false").lower() == "true"
    CAPTURE_ENABLED: bool = os.getenv("CAPTURE_ENABLED", "false").lower() == "true"
    CAPTURE_INTERFACE: str = os.getenv("CAPTURE_INTERFACE", "")
    CAPTURE_FILTER: str = os.getenv("CAPTURE_FILTER", "")
    FLOW_IDLE_TIMEOUT: int = int(os.getenv("FLOW_IDLE_TIMEOUT", "120"))
    FLOW_ACTIVE_TIMEOUT: int = int(os.getenv("FLOW_ACTIVE_TIMEOUT", "120"))
    FLOW_MODEL_MODE: str = os.getenv("FLOW_MODEL_MODE", "shadow")
    FLOW_ALERT_CONFIDENCE: float = float(os.getenv("FLOW_ALERT_CONFIDENCE", "0.90"))
    AUTO_BLOCK_ON_CRITICAL_IOC_MATCH: bool = os.getenv("AUTO_BLOCK_ON_CRITICAL_IOC_MATCH", "false").lower() == "true"
    EVENT_BATCH_MAX: int = int(os.getenv("EVENT_BATCH_MAX", "500"))
    EVENT_RETENTION_DAYS: int = int(os.getenv("EVENT_RETENTION_DAYS", "7"))

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
