"""
WolfEye — Flask Application Factory
=====================================
All extensions are created here and lazily initialised inside create_app()
so that the app can be instantiated multiple times during testing without
side-effects (standard Flask pattern).
"""

from __future__ import annotations

import logging
import os
import importlib

from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

# ---------------------------------------------------------------------------
# Extension instances (initialised without an app — bound later via init_app)
# ---------------------------------------------------------------------------

db = SQLAlchemy()
limiter = Limiter(key_func=get_remote_address)


def create_app(config_name: str | None = None) -> Flask:
    """
    Application factory.

    Args:
        config_name: ``"development"`` | ``"production"`` | ``"testing"``.
            Falls back to ``FLASK_ENV`` env var, then ``development``.

    Returns:
        A fully configured :class:`Flask` application instance.
    """
    app = Flask(__name__, instance_relative_config=True)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    from app.config import config_map  # local import avoids circular refs

    env = config_name or os.getenv("FLASK_ENV", "development")
    cfg = config_map.get(env, config_map["development"])
    app.config.from_object(cfg)

    # Ensure the instance folder exists (SQLite database lives here in dev)
    os.makedirs(app.instance_path, exist_ok=True)

    # ------------------------------------------------------------------
    # Extensions
    # ------------------------------------------------------------------
    db.init_app(app)
    limiter.init_app(app)
    CORS(app, supports_credentials=True)

    # ------------------------------------------------------------------
    # Blueprints
    # ------------------------------------------------------------------
    from app.routes.auth import auth_bp
    from app.routes.alerts import alerts_bp
    from app.routes.iocs import iocs_bp
    from app.routes.stats import stats_bp
    from app.routes.system import system_bp
    from app.routes.observations import observations_bp
    from app.routes.integrations import integrations_bp
    from app.routes.main import main_bp
    from app.routes.enforcement import enforcement_bp
    from app.routes.review import review_bp
    from app.routes.detections import detections_bp

    for bp in (
        main_bp,
        auth_bp,
        iocs_bp,
        alerts_bp,
        stats_bp,
        system_bp,
        observations_bp,
        integrations_bp,
        enforcement_bp,
        review_bp,
        detections_bp,
    ):
        app.register_blueprint(bp)

    # ------------------------------------------------------------------
    # Database — create tables on first run
    # ------------------------------------------------------------------
    with app.app_context():
        # Import models so SQLAlchemy is aware of them before create_all()
        importlib.import_module("app.models")
        db.create_all()
        _migrate_sqlite_schema()
        _seed_default_users(app)

    if app.config.get("INLINE_ENABLED") and not app.config.get("TESTING"):
        from app.services.inline import FlaskInlineMiddleware, build_policy

        app.wsgi_app = FlaskInlineMiddleware(
            app.wsgi_app,
            build_policy(app.config),
            mode=app.config.get("NODE_MODE", "gateway"),
            node_id=app.config.get("NODE_NAME", "default-node"),
        )

    # ------------------------------------------------------------------
    # Scheduler — start background jobs (skip during testing)
    # ------------------------------------------------------------------
    if not app.config.get("TESTING"):
        from app.services.scheduler import start_scheduler
        start_scheduler(app)

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    return app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _migrate_sqlite_schema() -> None:
    """Apply additive schema changes for existing local SQLite databases.

    ``db.create_all()`` does not update tables that already exist. Keeping
    these migrations here makes local upgrades safe without requiring users
    to delete their development database.
    """
    if db.engine.dialect.name != "sqlite":
        return

    migrations = {
        "ioc": {
            "risk_score": "FLOAT",
            "score_method": "VARCHAR(32) NOT NULL DEFAULT 'unset'",
        },
        "alert": {
            "risk_score": "FLOAT",
        },
        "audit_log": {
            "actor_type": "VARCHAR(32) NOT NULL DEFAULT 'system'",
            "node_id": "INTEGER",
        },
    }

    with db.engine.begin() as connection:
        for table, columns in migrations.items():
            existing = {
                row[1]
                for row in connection.execute(text(f"PRAGMA table_info({table})"))
            }
            for column, definition in columns.items():
                if column not in existing:
                    connection.execute(
                        text(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
                    )

            if table == "ioc" and "risk_score" not in existing:
                connection.execute(
                    text(
                        "UPDATE ioc SET risk_score = anomaly_score "
                        "WHERE risk_score IS NULL"
                    )
                )
            if table == "ioc" and "score_method" not in existing:
                connection.execute(
                    text(
                        "UPDATE ioc SET score_method = 'heuristic' "
                        "WHERE risk_score IS NOT NULL AND score_method = 'unset'"
                    )
                )
            if table == "alert" and "risk_score" not in existing:
                connection.execute(
                    text(
                        "UPDATE alert SET risk_score = anomaly_score "
                        "WHERE risk_score IS NULL"
                    )
                )


def _seed_default_users(app: Flask) -> None:
    """Create the demo and admin users if they do not already exist."""
    from app.models.user import User

    demo_username = app.config.get("DEMO_USERNAME", "demo")
    demo_password = app.config.get("DEMO_PASSWORD", "wolfeye-demo")
    analyst_username = app.config.get("ANALYST_USERNAME", "analyst")
    analyst_password = app.config.get("ANALYST_PASSWORD", "wolfeye-analyst")
    admin_username = app.config.get("ADMIN_USERNAME", "admin")
    admin_password = app.config.get("ADMIN_PASSWORD", "change-me-admin-password")

    if not User.query.filter_by(username=demo_username).first():
        demo = User(
            username=demo_username,
            role="readonly",
        )
        demo.set_password(demo_password)
        db.session.add(demo)

    if not User.query.filter_by(username=analyst_username).first():
        analyst = User(
            username=analyst_username,
            role="analyst",
        )
        analyst.set_password(analyst_password)
        db.session.add(analyst)

    if not User.query.filter_by(username=admin_username).first():
        admin = User(
            username=admin_username,
            role="admin",
        )
        admin.set_password(admin_password)
        db.session.add(admin)

    db.session.commit()
