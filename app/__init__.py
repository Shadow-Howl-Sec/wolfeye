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

    for bp in (
        main_bp,
        auth_bp,
        iocs_bp,
        alerts_bp,
        stats_bp,
        system_bp,
        observations_bp,
        integrations_bp,
    ):
        app.register_blueprint(bp)

    # ------------------------------------------------------------------
    # Database — create tables on first run
    # ------------------------------------------------------------------
    with app.app_context():
        # Import models so SQLAlchemy is aware of them before create_all()
        importlib.import_module("app.models")
        db.create_all()
        _seed_default_users(app)

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

def _seed_default_users(app: Flask) -> None:
    """Create the demo and admin users if they do not already exist."""
    from app.models.user import User

    demo_username = app.config.get("DEMO_USERNAME", "demo")
    admin_username = app.config.get("ADMIN_USERNAME", "admin")

    if not User.query.filter_by(username=demo_username).first():
        demo = User(
            username=demo_username,
            role="readonly",
        )
        demo.set_password(app.config.get("DEMO_PASSWORD", "wolfeye-demo"))
        db.session.add(demo)

    if not User.query.filter_by(username=admin_username).first():
        admin = User(
            username=admin_username,
            role="admin",
        )
        admin.set_password(app.config.get("ADMIN_PASSWORD", "change-me"))
        db.session.add(admin)

    db.session.commit()
