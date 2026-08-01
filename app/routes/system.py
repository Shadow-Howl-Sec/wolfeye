"""
app/routes/system.py
---------------------
System health and operational endpoints.

GET /api/system/health    — scheduler job status, db connection check
GET /api/system/ping      — liveness probe (used by UptimeRobot)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from flask import Blueprint, jsonify

from app import db

logger = logging.getLogger(__name__)

system_bp = Blueprint("system", __name__, url_prefix="/api/system")


@system_bp.route("/ping", methods=["GET"])
def ping():
    """
    Liveness probe — always returns 200 OK.
    UptimeRobot hits this every 5 minutes to prevent Render free-tier sleep.
    """
    return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}), 200


@system_bp.route("/health", methods=["GET"])
def health():
    """
    Detailed health check — reports:
        * Database connectivity
        * Scheduler job statuses (last run, last result, last error)
        * IOC / Alert counts
    """
    from app.services.scheduler import get_job_status
    from app.models.ioc import IOC
    from app.models.alert import Alert

    # DB check
    db_ok = False
    db_error = None
    try:
        db.session.execute(db.text("SELECT 1"))
        db_ok = True
    except Exception as exc:
        db_error = str(exc)

    # Counts
    try:
        ioc_count = IOC.query.count()
        alert_count = Alert.query.count()
        open_alerts = Alert.query.filter_by(status="open").count()
    except Exception:
        ioc_count = alert_count = open_alerts = None

    return jsonify({
        "status": "healthy" if db_ok else "degraded",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": {
            "connected": db_ok,
            "error": db_error,
        },
        "counts": {
            "iocs": ioc_count,
            "alerts": alert_count,
            "open_alerts": open_alerts,
        },
        "scheduler": get_job_status(),
    }), 200 if db_ok else 503
