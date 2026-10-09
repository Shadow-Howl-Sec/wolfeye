"""
app/routes/stats.py
--------------------
Statistics endpoints consumed by Member C's Chart.js graphs and
Leaflet geographic map.

GET /api/stats/trends          — daily IOC counts over last N days
GET /api/stats/top-countries   — top N countries by IOC count
GET /api/stats/severity-mix    — alert count grouped by severity
GET /api/stats/ioc-type-mix    — IOC count grouped by type
GET /api/stats/top-sources     — IOC count grouped by feed source
GET /api/stats/summary         — high-level dashboard numbers
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request
from sqlalchemy import func

from app import db
from app.models.ioc import IOC
from app.models.alert import Alert, AlertSeverity
from app.models.enrichment import Enrichment

logger = logging.getLogger(__name__)

stats_bp = Blueprint("stats", __name__, url_prefix="/api/stats")


# ---------------------------------------------------------------------------
# Helper: date range
# ---------------------------------------------------------------------------

def _days_ago(n: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=n)


# ---------------------------------------------------------------------------
# GET /api/stats/summary
# ---------------------------------------------------------------------------

@stats_bp.route("/summary", methods=["GET"])
def summary():
    """
    High-level dashboard numbers.

    Returns:
        total_iocs, new_iocs_24h, open_alerts, critical_alerts,
        watchlisted_iocs, iocs_with_score, enriched_iocs
    """
    cutoff_24h = _days_ago(1)

    total_iocs = IOC.query.count()
    new_24h = IOC.query.filter(IOC.created_at >= cutoff_24h).count()
    open_alerts = Alert.query.filter_by(status="open").count()
    critical_alerts = Alert.query.filter_by(severity=AlertSeverity.CRITICAL, status="open").count()
    watchlisted = IOC.query.filter_by(watchlisted=True).count()
    with_score = IOC.query.filter(IOC.anomaly_score.isnot(None)).count()
    enriched = db.session.query(func.count(Enrichment.id)).scalar()
    resolved_today = Alert.query.filter(
        Alert.status == "resolved", Alert.updated_at >= cutoff_24h
    ).count()

    return jsonify({
        "total_iocs": total_iocs,
        "new_iocs_24h": new_24h,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
        "watchlisted_iocs": watchlisted,
        "iocs_with_score": with_score,
        "enriched_iocs": enriched,
        "resolved_alerts_24h": resolved_today,
        "high_severity_alerts": Alert.query.filter(
            Alert.severity.in_([AlertSeverity.HIGH, AlertSeverity.CRITICAL]),
            Alert.status == "open",
        ).count(),
    }), 200


# ---------------------------------------------------------------------------
# GET /api/stats/trends
# ---------------------------------------------------------------------------

@stats_bp.route("/trends", methods=["GET"])
def trends():
    """
    Daily IOC ingestion count for the last N days.

    Query params:
        days  int  (default 30, max 90)

    Returns:
        [{date: "YYYY-MM-DD", count: N}, ...]
    """
    days = min(request.args.get("days", 30, type=int), 90)
    cutoff = _days_ago(days)

    rows = (
        db.session.query(
            func.date(IOC.created_at).label("day"),
            func.count(IOC.id).label("count"),
        )
        .filter(IOC.created_at >= cutoff)
        .group_by(func.date(IOC.created_at))
        .order_by(func.date(IOC.created_at).asc())
        .all()
    )

    return jsonify([{"date": str(r.day), "count": r.count} for r in rows]), 200


# ---------------------------------------------------------------------------
# GET /api/stats/top-countries
# ---------------------------------------------------------------------------

@stats_bp.route("/top-countries", methods=["GET"])
def top_countries():
    """
    Top N countries by IOC count (via Enrichment.country).

    Query params:
        limit  int  (default 10, max 50)

    Returns:
        [{country: "US", count: N}, ...]
    """
    limit = min(request.args.get("limit", 10, type=int), 50)

    rows = (
        db.session.query(
            Enrichment.country,
            func.count(Enrichment.id).label("count"),
        )
        .filter(Enrichment.country.isnot(None))
        .group_by(Enrichment.country)
        .order_by(func.count(Enrichment.id).desc())
        .limit(limit)
        .all()
    )

    centroids = {
        "US": (38.9, -77.0), "GB": (51.5, -0.1), "DE": (52.5, 13.4),
        "FR": (48.9, 2.3), "NL": (52.1, 5.1), "RU": (55.8, 37.6),
        "CN": (39.9, 116.4), "IN": (28.6, 77.2), "BR": (-15.8, -47.9),
        "CA": (45.4, -75.7), "AU": (-35.3, 149.1),
    }
    return jsonify([
        {"country": r.country, "count": r.count,
         "latitude": centroids.get(r.country, (None, None))[0],
         "longitude": centroids.get(r.country, (None, None))[1]}
        for r in rows
    ]), 200


# ---------------------------------------------------------------------------
# GET /api/stats/severity-mix
# ---------------------------------------------------------------------------

@stats_bp.route("/severity-mix", methods=["GET"])
def severity_mix():
    """
    Alert count grouped by severity (all-time or last N days).

    Query params:
        days  int  optional lookback window

    Returns:
        [{severity: "critical", count: N}, ...]
    """
    days = request.args.get("days", type=int)
    query = db.session.query(
        Alert.severity,
        func.count(Alert.id).label("count"),
    )
    if days:
        query = query.filter(Alert.created_at >= _days_ago(days))

    rows = query.group_by(Alert.severity).order_by(func.count(Alert.id).desc()).all()

    return jsonify([{"severity": r.severity, "count": r.count} for r in rows]), 200


# ---------------------------------------------------------------------------
# GET /api/stats/ioc-type-mix
# ---------------------------------------------------------------------------

@stats_bp.route("/ioc-type-mix", methods=["GET"])
def ioc_type_mix():
    """IOC count grouped by indicator type (ip, domain, url, hash)."""
    rows = (
        db.session.query(
            IOC.type,
            func.count(IOC.id).label("count"),
        )
        .group_by(IOC.type)
        .order_by(func.count(IOC.id).desc())
        .all()
    )
    return jsonify([{"type": r.type, "count": r.count} for r in rows]), 200


# ---------------------------------------------------------------------------
# GET /api/stats/top-sources
# ---------------------------------------------------------------------------

@stats_bp.route("/top-sources", methods=["GET"])
def top_sources():
    """IOC count grouped by feed source."""
    rows = (
        db.session.query(
            IOC.source,
            func.count(IOC.id).label("count"),
        )
        .group_by(IOC.source)
        .order_by(func.count(IOC.id).desc())
        .all()
    )
    return jsonify([{"source": r.source, "count": r.count} for r in rows]), 200
