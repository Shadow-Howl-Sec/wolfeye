"""
app/routes/alerts.py
---------------------
Alert REST API endpoints.

GET    /api/alerts          — list alerts with severity / status filters
GET    /api/alerts/<id>     — single alert detail
POST   /api/alerts/<id>/resolve  — resolve an alert (admin)
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request, session, Response

from app import limiter
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.routes.auth import login_required, admin_required
from app.services.playbooks import resolve_alert
from app.services.reports import build_incident_report

logger = logging.getLogger(__name__)

alerts_bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")

PAGE_SIZE_DEFAULT = 20
PAGE_SIZE_MAX = 100


@alerts_bp.route("", methods=["GET"])
def list_alerts():
    """
    List alerts with optional severity/status filtering and pagination.

    Query params:
        page        int
        per_page    int
        severity    low | medium | high | critical
        status      open | investigating | resolved | false_positive
        ioc_id      int — filter by IOC
        sort        created_at | severity | anomaly_score (default: created_at)
        order       asc | desc (default: desc)
    """
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(
        request.args.get("per_page", PAGE_SIZE_DEFAULT, type=int),
        PAGE_SIZE_MAX,
    )

    query = Alert.query

    if severity := request.args.get("severity"):
        query = query.filter(Alert.severity == severity.lower())
    if status := request.args.get("status"):
        query = query.filter(Alert.status == status.lower())
    if ioc_id := request.args.get("ioc_id", type=int):
        query = query.filter(Alert.ioc_id == ioc_id)

    # Sorting
    sort_field = request.args.get("sort", "created_at")
    order = request.args.get("order", "desc")
    sort_col = {
        "created_at": Alert.created_at,
        "severity": Alert.severity,
        "anomaly_score": Alert.anomaly_score,
    }.get(sort_field, Alert.created_at)

    if order == "asc":
        query = query.order_by(sort_col.asc())
    else:
        query = query.order_by(sort_col.desc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        "data": [a.to_dict(include_ioc=True) for a in pagination.items],
        "meta": {
            "page": page,
            "per_page": per_page,
            "total": pagination.total,
            "pages": pagination.pages,
        },
    }), 200


@alerts_bp.route("/<int:alert_id>", methods=["GET"])
def get_alert(alert_id: int):
    """Return a single alert with its linked IOC."""
    alert = Alert.query.get_or_404(alert_id)
    return jsonify(alert.to_dict(include_ioc=True)), 200


@alerts_bp.route("/<int:alert_id>/resolve", methods=["POST"])
@admin_required
@limiter.limit("30 per minute")
def resolve(alert_id: int):
    """
    Resolve an open alert.

    Request body (JSON, optional):
        {"notes": "False positive — internal scanner"}
    """
    data = request.get_json(silent=True) or {}
    notes = data.get("notes")
    performed_by = session.get("username", "analyst")

    try:
        alert = resolve_alert(alert_id, performed_by, notes)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404

    return jsonify({"message": "Alert resolved", "alert": alert.to_dict()}), 200


@alerts_bp.route("/<int:alert_id>/report", methods=["GET"])
def report(alert_id: int):
    """Generate a PDF incident report for an alert."""
    try:
        pdf = build_incident_report(alert_id)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        logger.error("Incident report generation failed: %s", exc)
        return jsonify({"error": "PDF generation is unavailable", "detail": str(exc)}), 503
    return Response(pdf, mimetype="application/pdf",
                    headers={"Content-Disposition": f"attachment; filename=wolfeye_alert_{alert_id}.pdf"})
