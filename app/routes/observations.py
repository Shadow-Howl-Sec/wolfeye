"""Authenticated ingestion endpoint for local security-agent observations."""

from __future__ import annotations

from functools import wraps

from flask import Blueprint, current_app, jsonify, request, session

from app import limiter
from app.services.ingestion import ingest_iocs
from app.services.telemetry import extract_observation_iocs

observations_bp = Blueprint("observations", __name__, url_prefix="/api/observations")


def agent_or_admin_required(view):
    """Allow a configured agent token or an authenticated admin session."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        expected = current_app.config.get("LOCAL_INGEST_TOKEN", "")
        supplied = request.headers.get("X-WolfEye-Agent-Token", "")
        if expected and supplied and supplied == expected:
            return view(*args, **kwargs)
        if session.get("user_role") == "admin":
            return view(*args, **kwargs)
        return jsonify({"error": "Admin session or agent token required"}), 401
    return wrapped


@observations_bp.route("", methods=["POST"])
@agent_or_admin_required
@limiter.limit("120 per minute")
def receive_observation():
    """Receive metadata from a host agent and extract indicators locally."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON object required"}), 400
    events = payload.get("events", [payload])
    if not isinstance(events, list) or not events or len(events) > 100:
        return jsonify({"error": "events must contain 1-100 objects"}), 400
    if not all(isinstance(event, dict) for event in events):
        return jsonify({"error": "each event must be an object"}), 400

    agent_id = str(payload.get("agent_id", "unknown"))[:64]
    source = f"agent:{agent_id}"
    iocs = []
    for event in events:
        iocs.extend(extract_observation_iocs(event, source))
    inserted, duplicates = ingest_iocs(iocs)
    return jsonify({
        "accepted_events": len(events),
        "indicators_found": len(iocs),
        "inserted": inserted,
        "duplicates": duplicates,
        "content_stored": False,
    }), 202