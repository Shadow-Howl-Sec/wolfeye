"""Live IOC scoring using enrichment evidence and safe fallback heuristics."""

from __future__ import annotations

import logging
from typing import Any

from app import db
from app.models.audit_log import AuditAction, AuditLog
from app.models.enrichment import Enrichment
from app.models.ioc import IOC

logger = logging.getLogger(__name__)


def score_ioc(ioc: IOC) -> float:
    """Return a bounded threat score from live reputation evidence."""
    enrichment = ioc.enrichment
    score = 0.0
    if ioc.source in {"urlhaus", "threatfox", "malwarebazaar", "feodo_tracker"}:
        score += 0.55
    if enrichment:
        score += min((enrichment.vt_detections or 0) / 20.0, 0.25)
        score += min((enrichment.abuseipdb_score or 0) / 400.0, 0.25)
        score += min(len(enrichment.shodan_ports_list) / 40.0, 0.10)
        if enrichment.vt_reputation is not None and enrichment.vt_reputation < 0:
            score += 0.10
    return round(min(score, 1.0), 4)


def score_pending_iocs(app: Any, batch_size: int = 200) -> dict[str, int]:
    """Score newly ingested or re-enriched IOCs and audit each decision."""
    with app.app_context():
        iocs = (
            IOC.query.filter(IOC.anomaly_score.is_(None))
            .order_by(IOC.created_at.asc())
            .limit(batch_size)
            .all()
        )
        for ioc in iocs:
            ioc.anomaly_score = score_ioc(ioc)
            db.session.add(AuditLog(
                ioc_id=ioc.id,
                action=AuditAction.SCORED,
                performed_by="system",
                detail=f"live_evidence_score={ioc.anomaly_score:.4f}",
            ))
        db.session.commit()
        logger.info("Scored %d pending IOCs", len(iocs))
        return {"scored": len(iocs)}