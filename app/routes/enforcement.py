"""app/routes/enforcement.py
---------------------------
Enforcement and list-management APIs for the data-plane control loop.

Endpoints exposed:
    GET  /api/enforcement/lists
    POST /api/enforcement/blocks
    DELETE /api/enforcement/blocks/<id>
    POST /api/enforcement/allows
    DELETE /api/enforcement/allows/<id>
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request, session

from app import db
from app.models.allow_entry import AllowEntry
from app.models.block_entry import BlockEntry
from app.models.config_setting import ConfigSetting
from app.models.node import Node
from app.routes.auth import analyst_required

logger = logging.getLogger(__name__)

enforcement_bp = Blueprint("enforcement", __name__, url_prefix="/api/enforcement")


def _current_list_version() -> int:
    """Return the current enforcement-list version number."""
    version_value = ConfigSetting.query.filter_by(key="enforcement_list_version").first()
    if version_value is None:
        return 1
    try:
        return max(1, int(version_value.value))
    except (TypeError, ValueError):
        return 1


def _bump_list_version() -> int:
    """Increment the enforcement list version and persist it."""
    current = _current_list_version()
    next_version = current + 1
    row = ConfigSetting.query.filter_by(key="enforcement_list_version").first()
    if row is None:
        row = ConfigSetting(key="enforcement_list_version", value=str(next_version))
        db.session.add(row)
    else:
        row.value = str(next_version)
    db.session.commit()
    return next_version


@enforcement_bp.route("/lists", methods=["GET"])
def list_entries():
    """Return active blocklist + allowlist entries plus a monotonically increasing version."""
    blocks = [
        entry.to_dict()
        for entry in BlockEntry.query.filter_by(active=True).order_by(BlockEntry.created_at.desc()).all()
    ]
    allows = [
        entry.to_dict()
        for entry in AllowEntry.query.order_by(AllowEntry.created_at.desc()).all()
    ]
    version = _current_list_version()
    return jsonify({
        "version": version,
        "blocklist": blocks,
        "allowlist": allows,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }), 200


@enforcement_bp.route("/blocks", methods=["POST"])
@analyst_required
def create_block():
    """Create a blocklist entry for an analyst or admin decision."""
    data = request.get_json(silent=True) or {}
    kind = (data.get("kind") or "ip").strip().lower()
    value = str(data.get("value") or "").strip()
    reason = str(data.get("reason") or "manual block").strip()
    ttl_minutes = data.get("ttl")

    if not kind or not value:
        return jsonify({"error": "kind and value are required"}), 400

    if kind not in {"ip", "cidr", "domain", "url_prefix"}:
        return jsonify({"error": "unsupported kind"}), 400

    try:
        ttl_seconds = int(ttl_minutes) if ttl_minutes is not None else None
    except (TypeError, ValueError):
        return jsonify({"error": "ttl must be an integer number of seconds"}), 400

    expires_at = None
    if ttl_seconds is not None and ttl_seconds > 0:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

    entry = BlockEntry(
        kind=kind,
        value=value,
        reason=reason,
        source="expert",
        created_by=session.get("username", "analyst"),
        expires_at=expires_at,
        active=True,
    )
    db.session.add(entry)
    db.session.commit()
    _bump_list_version()
    logger.info("Created block entry %s for %s by %s", kind, value, entry.created_by)
    return jsonify({"message": "Block entry created", "entry": entry.to_dict()}), 201


@enforcement_bp.route("/blocks/<int:block_id>", methods=["DELETE"])
@analyst_required
def remove_block(block_id: int):
    """Deactivate a blocklist entry."""
    entry = BlockEntry.query.get_or_404(block_id)
    entry.active = False
    db.session.commit()
    _bump_list_version()
    return jsonify({"message": "Block entry removed", "entry": entry.to_dict()}), 200


@enforcement_bp.route("/allows", methods=["POST"])
@analyst_required
def create_allow():
    """Create an allowlist entry."""
    data = request.get_json(silent=True) or {}
    kind = (data.get("kind") or "ip").strip().lower()
    value = str(data.get("value") or "").strip()
    reason = str(data.get("reason") or "manual allow").strip()
    ttl_seconds = data.get("ttl")

    if not kind or not value:
        return jsonify({"error": "kind and value are required"}), 400

    expires_at = None
    if ttl_seconds is not None:
        try:
            ttl_seconds = int(ttl_seconds)
        except (TypeError, ValueError):
            return jsonify({"error": "ttl must be an integer number of seconds"}), 400
        if ttl_seconds > 0:
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

    entry = AllowEntry(
        kind=kind,
        value=value,
        reason=reason,
        created_by=session.get("username", "analyst"),
        expires_at=expires_at,
    )
    db.session.add(entry)
    db.session.commit()
    _bump_list_version()
    logger.info("Created allow entry %s for %s by %s", kind, value, entry.created_by)
    return jsonify({"message": "Allow entry created", "entry": entry.to_dict()}), 201


@enforcement_bp.route("/allows/<int:allow_id>", methods=["DELETE"])
@analyst_required
def remove_allow(allow_id: int):
    """Delete an allowlist entry."""
    entry = AllowEntry.query.get_or_404(allow_id)
    db.session.delete(entry)
    db.session.commit()
    _bump_list_version()
    return jsonify({"message": "Allow entry removed", "entry": {"id": allow_id}}), 200
