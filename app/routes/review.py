"""app/routes/review.py
----------------------
Expert review workflow endpoints for alerts and associated evidence.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, session

from app import db
from app.models.alert import Alert, AlertStatus
from app.models.audit_log import AuditAction, AuditLog
from app.models.block_entry import BlockEntry
from app.models.review_item import ReviewItem
from app.routes.auth import analyst_required

logger = logging.getLogger(__name__)

review_bp = Blueprint("review", __name__, url_prefix="/api/review")


def _parse_subject_kind(value: str) -> str:
    value = (value or "").strip()
    if value.startswith("http://") or value.startswith("https://"):
        return "url"
    if "/" in value and "." in value:
        return "domain"
    return "ip"


def _build_review_item(alert: Alert) -> ReviewItem:
    ioc = alert.ioc
    evidence = {
        "ioc_id": ioc.id,
        "ioc_value": ioc.value,
        "ioc_type": ioc.type,
        "risk_score": ioc.risk_score,
        "anomaly_score": ioc.anomaly_score,
        "severity": alert.severity,
        "status": alert.status,
        "created_at": alert.created_at.isoformat(),
        "source": ioc.source,
    }

    existing = ReviewItem.query.filter_by(alert_id=alert.id).first()
    if existing is not None:
        return existing

    item = ReviewItem(
        alert_id=alert.id,
        subject=ioc.value,
        evidence_json=json.dumps(evidence),
        status="open",
    )
    db.session.add(item)
    db.session.commit()
    return item


@review_bp.route("", methods=["GET"])
def list_review_items():
    """List expert review items filtered by status, severity, or IOC."""
    query = ReviewItem.query.join(ReviewItem.alert)
    status = request.args.get("status")
    if status:
        query = query.filter(ReviewItem.status == status)
    severity = request.args.get("severity")
    if severity:
        query = query.filter(Alert.severity == severity.lower())
    ioc_id = request.args.get("ioc_id", type=int)
    if ioc_id:
        query = query.filter(Alert.ioc_id == ioc_id)

    items = query.order_by(ReviewItem.created_at.desc()).all()
    return jsonify({
        "data": [
            {
                "id": item.id,
                "alert_id": item.alert_id,
                "subject": item.subject,
                "status": item.status,
                "severity": item.alert.severity,
                "risk_score": item.alert.risk_score,
                "anomaly_score": item.alert.anomaly_score,
                "created_at": item.created_at.isoformat(),
            }
            for item in items
        ],
        "meta": {"total": len(items)},
    }), 200


@review_bp.route("/alerts/<int:alert_id>", methods=["POST"])
@analyst_required
def create_review_item(alert_id: int):
    """Put an alert into the expert review queue."""
    alert = Alert.query.get_or_404(alert_id)
    item = _build_review_item(alert)
    return jsonify({"item": item.to_dict()}), 201


@review_bp.route("/<int:review_id>", methods=["GET"])
def get_review_item(review_id: int):
    """View the detailed evidence for a review item."""
    item = ReviewItem.query.get_or_404(review_id)
    payload = item.to_dict()
    payload["alert"] = item.alert.to_dict(include_ioc=True)
    return jsonify(payload), 200


@review_bp.route("/<int:review_id>/block", methods=["POST"])
@analyst_required
def block_review_item(review_id: int):
    """Create a block entry from a review-item decision."""
    item = ReviewItem.query.get_or_404(review_id)
    data = request.get_json(silent=True) or {}
    ttl_seconds = data.get("ttl")
    reason = str(data.get("reason") or "review decision").strip() or "review decision"

    kind = _parse_subject_kind(item.subject)
    expires_at = None
    if ttl_seconds is not None:
        try:
            ttl_seconds = int(ttl_seconds)
        except (TypeError, ValueError):
            return jsonify({"error": "ttl must be an integer number of seconds"}), 400
        if ttl_seconds > 0:
            expires_at = datetime.now(timezone.utc)
            expires_at = expires_at.replace(microsecond=0)
            from datetime import timedelta
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

    entry = BlockEntry(
        kind=kind,
        value=item.subject,
        reason=reason,
        source="expert",
        created_by=session.get("username", "analyst"),
        expires_at=expires_at,
        active=True,
        related_alert_id=item.alert_id,
    )
    db.session.add(entry)

    item.status = "blocked"
    item.decided_by = session.get("username", "analyst")
    item.decided_at = datetime.now(timezone.utc)
    item.decision_note = reason

    Alert.query.filter_by(id=item.alert_id).update({"status": AlertStatus.INVESTIGATING})

    audit = AuditLog(
        ioc_id=item.alert.ioc_id,
        action=AuditAction.BLOCK_CREATED,
        performed_by=item.decided_by,
        actor_type="user",
        detail=f"Review item {review_id} blocked: {reason}",
    )
    db.session.add(audit)
    db.session.commit()

    return jsonify({"message": "Review item blocked", "entry": entry.to_dict(), "item": item.to_dict()}), 200


@review_bp.route("/<int:review_id>/clear", methods=["POST"])
@analyst_required
def clear_review_item(review_id: int):
    """Mark a review item as safe; optionally add an allow entry."""
    item = ReviewItem.query.get_or_404(review_id)
    data = request.get_json(silent=True) or {}
    reason = str(data.get("reason") or "marked safe by analyst").strip() or "marked safe by analyst"
    ttl_seconds = data.get("ttl")

    expires_at = None
    if ttl_seconds is not None:
        try:
            ttl_seconds = int(ttl_seconds)
        except (TypeError, ValueError):
            return jsonify({"error": "ttl must be an integer number of seconds"}), 400
        if ttl_seconds > 0:
            from datetime import timedelta
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

    if data.get("allow") is not False:
        kind = _parse_subject_kind(item.subject)
        allow = item.subject
        db.session.add(
            __import__("app.models.allow_entry", fromlist=["AllowEntry"]).AllowEntry(
                kind=kind,
                value=allow,
                reason=reason,
                created_by=session.get("username", "analyst"),
                expires_at=expires_at,
            )
        )

    item.status = "cleared"
    item.decided_by = session.get("username", "analyst")
    item.decided_at = datetime.now(timezone.utc)
    item.decision_note = reason
    db.session.add(
        AuditLog(
            ioc_id=item.alert.ioc_id,
            action=AuditAction.ALLOW_CREATED,
            performed_by=item.decided_by,
            actor_type="user",
            detail=f"Review item {review_id} cleared: {reason}",
        )
    )
    db.session.commit()
    return jsonify({"message": "Review item cleared", "item": item.to_dict()}), 200
