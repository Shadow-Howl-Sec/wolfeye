"""Live IOC scoring using enrichment evidence and safe fallback heuristics."""

from __future__ import annotations

import logging
import hashlib
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
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
        all_iocs = IOC.query.all()
        if len(all_iocs) >= 5:
            features = np.asarray([_features(ioc) for ioc in all_iocs], dtype=float)
            model = IsolationForest(
                n_estimators=100, contamination="auto", random_state=42, n_jobs=-1
            )
            model.fit(features)
            raw = -model.decision_function(features)
            low, high = float(raw.min()), float(raw.max())
            scores = (raw - low) / (high - low) if high > low else np.full(len(raw), 0.5)
            score_by_id = {ioc.id: round(float(score), 4)
                           for ioc, score in zip(all_iocs, scores)}
        else:
            score_by_id = {ioc.id: score_ioc(ioc) for ioc in iocs}
        for ioc in iocs:
            ioc.anomaly_score = score_by_id[ioc.id]
            db.session.add(AuditLog(
                ioc_id=ioc.id,
                action=AuditAction.SCORED,
                performed_by="system",
                detail=f"isolation_forest_score={ioc.anomaly_score:.4f}",
            ))
        db.session.commit()
        logger.info("Scored %d pending IOCs", len(iocs))
        return {"scored": len(iocs)}


def _features(ioc: IOC) -> list[float]:
    enrichment = ioc.enrichment
    source_hash = int(hashlib.sha256(ioc.source.encode()).hexdigest()[:8], 16) / 2**32
    type_hash = int(hashlib.sha256(ioc.type.encode()).hexdigest()[:8], 16) / 2**32
    return [
        len(ioc.value) / 2048.0,
        type_hash,
        source_hash,
        float(enrichment.vt_detections or 0) if enrichment else 0.0,
        float(enrichment.abuseipdb_score or 0) if enrichment else 0.0,
        float(len(enrichment.shodan_ports_list)) if enrichment else 0.0,
    ]