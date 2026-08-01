"""
app/routes/iocs.py
-------------------
IOC REST API endpoints.

GET  /api/iocs               — paginated list with filtering
GET  /api/iocs/<id>          — single IOC detail with enrichment + score
GET  /api/iocs/export        — CSV or JSON export
POST /api/iocs/<id>/investigate  — mark as investigated (admin)
POST /api/iocs/<id>/watchlist    — add to watchlist (admin)
DELETE /api/iocs/<id>/watchlist  — remove from watchlist (admin)
GET  /api/iocs/<id>/audit    — audit trail for an IOC
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request, Response, session

from app import db, limiter
from app.models.ioc import IOC, IOCType, IOCStatus
from app.models.enrichment import Enrichment
from app.routes.auth import login_required, admin_required
from app.services.playbooks import (
    mark_investigated,
    add_to_watchlist,
    remove_from_watchlist,
    export_iocs,
)

logger = logging.getLogger(__name__)

iocs_bp = Blueprint("iocs", __name__, url_prefix="/api/iocs")

PAGE_SIZE_DEFAULT = 20
PAGE_SIZE_MAX = 100


# ---------------------------------------------------------------------------
# GET /api/iocs
# ---------------------------------------------------------------------------

@iocs_bp.route("", methods=["GET"])
def list_iocs():
    """
    List IOCs with pagination, filtering, and search.

    Query params:
        page        int  (default 1)
        per_page    int  (default 20, max 100)
        type        str  ip | domain | url | hash
        source      str  urlhaus | threatfox | manual
        status      str  new | investigated | watchlisted | closed
        watchlisted bool true | false
        q           str  search substring in value
        min_score   float  minimum anomaly_score
        sort        str  score | created_at | first_seen (default: created_at)
        order       str  asc | desc (default: desc)
    """
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(
        request.args.get("per_page", PAGE_SIZE_DEFAULT, type=int),
        PAGE_SIZE_MAX,
    )

    query = IOC.query

    # Filters
    if ioc_type := request.args.get("type"):
        query = query.filter(IOC.type == ioc_type)
    if source := request.args.get("source"):
        query = query.filter(IOC.source == source)
    if status := request.args.get("status"):
        query = query.filter(IOC.status == status)
    if (watchlisted := request.args.get("watchlisted")) is not None:
        query = query.filter(IOC.watchlisted == (watchlisted.lower() == "true"))
    if q := request.args.get("q"):
        query = query.filter(IOC.value.ilike(f"%{q}%"))
    if min_score := request.args.get("min_score", type=float):
        query = query.filter(IOC.anomaly_score >= min_score)

    # Sorting
    sort_field = request.args.get("sort", "created_at")
    order = request.args.get("order", "desc")
    sort_col = {
        "score": IOC.anomaly_score,
        "created_at": IOC.created_at,
        "first_seen": IOC.first_seen,
    }.get(sort_field, IOC.created_at)

    if order == "asc":
        query = query.order_by(sort_col.asc())
    else:
        query = query.order_by(sort_col.desc())

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        "data": [ioc.to_dict() for ioc in pagination.items],
        "meta": {
            "page": page,
            "per_page": per_page,
            "total": pagination.total,
            "pages": pagination.pages,
            "has_next": pagination.has_next,
            "has_prev": pagination.has_prev,
        },
    }), 200


# ---------------------------------------------------------------------------
# GET /api/iocs/export
# ---------------------------------------------------------------------------

@iocs_bp.route("/export", methods=["GET"])
def export():
    """
    Export IOCs as CSV or JSON.

    Query params:
        ids   comma-separated IOC IDs (optional; exports all if omitted)
        fmt   csv | json (default: csv)
    """
    ids_raw = request.args.get("ids", "")
    ioc_ids = [int(i) for i in ids_raw.split(",") if i.strip().isdigit()] or None
    fmt = request.args.get("fmt", "csv").lower()
    if fmt not in ("csv", "json"):
        fmt = "csv"

    content, mimetype = export_iocs(ioc_ids, fmt)
    filename = f"wolfeye_iocs.{fmt}"
    return Response(
        content,
        mimetype=mimetype,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ---------------------------------------------------------------------------
# GET /api/iocs/<id>
# ---------------------------------------------------------------------------

@iocs_bp.route("/<int:ioc_id>", methods=["GET"])
def get_ioc(ioc_id: int):
    """Return a single IOC with enrichment data and anomaly score."""
    ioc = IOC.query.get_or_404(ioc_id)
    return jsonify(ioc.to_dict(include_enrichment=True)), 200


# ---------------------------------------------------------------------------
# GET /api/iocs/<id>/audit
# ---------------------------------------------------------------------------

@iocs_bp.route("/<int:ioc_id>/audit", methods=["GET"])
def get_audit(ioc_id: int):
    """Return the audit trail for a single IOC."""
    ioc = IOC.query.get_or_404(ioc_id)
    logs = [log.to_dict() for log in sorted(ioc.audit_logs, key=lambda l: l.timestamp)]
    return jsonify({"ioc_id": ioc_id, "audit_log": logs}), 200


# ---------------------------------------------------------------------------
# POST /api/iocs/<id>/investigate
# ---------------------------------------------------------------------------

@iocs_bp.route("/<int:ioc_id>/investigate", methods=["POST"])
@admin_required
@limiter.limit("30 per minute")
def investigate(ioc_id: int):
    """Mark an IOC as investigated. Requires admin role."""
    performed_by = session.get("username", "analyst")
    try:
        ioc = mark_investigated(ioc_id, performed_by)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify({"message": "IOC marked as investigated", "ioc": ioc.to_dict()}), 200


# ---------------------------------------------------------------------------
# POST /api/iocs/<id>/watchlist
# ---------------------------------------------------------------------------

@iocs_bp.route("/<int:ioc_id>/watchlist", methods=["POST"])
@admin_required
@limiter.limit("30 per minute")
def watchlist_add(ioc_id: int):
    """Add an IOC to the watchlist. Requires admin role."""
    performed_by = session.get("username", "analyst")
    try:
        ioc = add_to_watchlist(ioc_id, performed_by)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify({"message": "IOC added to watchlist", "ioc": ioc.to_dict()}), 200


@iocs_bp.route("/<int:ioc_id>/watchlist", methods=["DELETE"])
@admin_required
@limiter.limit("30 per minute")
def watchlist_remove(ioc_id: int):
    """Remove an IOC from the watchlist. Requires admin role."""
    performed_by = session.get("username", "analyst")
    try:
        ioc = remove_from_watchlist(ioc_id, performed_by)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify({"message": "IOC removed from watchlist", "ioc": ioc.to_dict()}), 200
