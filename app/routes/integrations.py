"""MISP and OpenCTI synchronization endpoints."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify

from app.routes.auth import admin_required
from app.models.ioc import IOC
from app.services.integrations import pull_misp, pull_opencti, publish_misp

integrations_bp = Blueprint("integrations", __name__, url_prefix="/api/integrations")


@integrations_bp.post("/misp/pull")
@admin_required
def misp_pull():
    try:
        return jsonify(pull_misp(current_app.config, limit=100)), 200
    except Exception as exc:
        current_app.logger.error("MISP pull failed: %s", exc)
        return jsonify({"error": "MISP pull failed", "detail": str(exc)}), 502


@integrations_bp.post("/misp/publish/<int:ioc_id>")
@admin_required
def misp_publish(ioc_id: int):
    ioc = IOC.query.get_or_404(ioc_id)
    try:
        event_id = publish_misp(ioc, current_app.config)
        return jsonify({"published": True, "event_id": event_id}), 201
    except Exception as exc:
        current_app.logger.error("MISP publish failed for IOC %d: %s", ioc_id, exc)
        return jsonify({"error": "MISP publish failed", "detail": str(exc)}), 502


@integrations_bp.post("/opencti/pull")
@admin_required
def opencti_pull():
    try:
        return jsonify(pull_opencti(current_app.config, limit=100)), 200
    except Exception as exc:
        current_app.logger.error("OpenCTI pull failed: %s", exc)
        return jsonify({"error": "OpenCTI pull failed", "detail": str(exc)}), 502
