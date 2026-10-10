"""Live IOC scoring using enrichment evidence and safe fallback heuristics."""

from __future__ import annotations

import logging
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from app import db
from app.models.audit_log import AuditAction, AuditLog
from app.models.ioc import IOC, ScoreMethod

logger = logging.getLogger(__name__)


def score_ioc(ioc: IOC) -> float:
    """Return the heuristic risk score used by the live decision engine."""
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
    """Score newly ingested or re-enriched IOCs, keeping risk and anomaly signals separate."""
    with app.app_context():
        iocs = (
            IOC.query.filter(IOC.risk_score.is_(None) | IOC.anomaly_score.is_(None))
            .order_by(IOC.created_at.asc())
            .limit(batch_size)
            .all()
        )
        all_iocs = IOC.query.all()

        score_by_id: dict[int, float] = {}
        anomaly_by_id: dict[int, float] = {}
        if len(all_iocs) >= 5:
            features = np.asarray([_features(ioc) for ioc in all_iocs], dtype=float)
            model = IsolationForest(
                n_estimators=100, contamination="auto", random_state=42, n_jobs=-1
            )
            model.fit(features)
            raw = -model.decision_function(features)
            low, high = float(raw.min()), float(raw.max())
            scores = (raw - low) / (high - low) if high > low else np.full(len(raw), 0.5)
            anomaly_by_id = {ioc.id: round(float(score), 4) for ioc, score in zip(all_iocs, scores)}

        for ioc in all_iocs:
            score_by_id[ioc.id] = score_ioc(ioc)
            ioc.risk_score = score_by_id[ioc.id]
            ioc.score_method = ScoreMethod.HEURISTIC
            if ioc.id in anomaly_by_id:
                ioc.anomaly_score = anomaly_by_id[ioc.id]

        for ioc in iocs:
            db.session.add(AuditLog(
                ioc_id=ioc.id,
                action=AuditAction.SCORED,
                performed_by="system",
                detail=(
                    f"risk_score={ioc.risk_score:.4f}; "
                    f"anomaly_score={ioc.anomaly_score:.4f} if {ioc.anomaly_score is not None} else "
                    "anomaly_score=none"
                ),
            ))

        db.session.commit()
        logger.info("Scored %d pending IOCs", len(iocs))
        return {"scored": len(iocs)}


def _features(ioc: IOC) -> list[float]:
    """Build a stable, explicit feature vector for the Isolation Forest model."""
    enrichment = ioc.enrichment
    type_bits = {"ip": 1.0 if ioc.type == "ip" else 0.0,
                 "domain": 1.0 if ioc.type == "domain" else 0.0,
                 "url": 1.0 if ioc.type == "url" else 0.0,
                 "hash": 1.0 if ioc.type == "hash" else 0.0,
                 "email": 1.0 if ioc.type == "email" else 0.0}
    source_bits = {"manual": 1.0 if ioc.source == "manual" else 0.0,
                   "urlhaus": 1.0 if ioc.source == "urlhaus" else 0.0,
                   "threatfox": 1.0 if ioc.source == "threatfox" else 0.0,
                   "malwarebazaar": 1.0 if ioc.source == "malwarebazaar" else 0.0,
                   "feodo_tracker": 1.0 if ioc.source == "feodo_tracker" else 0.0}
    vt_detections = (enrichment.vt_detections or 0) if enrichment else 0.0
    abuse_score = (enrichment.abuseipdb_score or 0) if enrichment else 0.0
    shodan_ports_count = float(len(enrichment.shodan_ports_list)) if enrichment else 0.0
    vt_reputation = float(enrichment.vt_reputation) if enrichment and enrichment.vt_reputation is not None else 0.0

    return [
        len(ioc.value) / 2048.0,
        type_bits["ip"],
        type_bits["domain"],
        type_bits["url"],
        type_bits["hash"],
        type_bits["email"],
        source_bits["manual"],
        source_bits["urlhaus"],
        source_bits["threatfox"],
        source_bits["malwarebazaar"],
        source_bits["feodo_tracker"],
        float(vt_detections),
        float(abuse_score),
        float(shodan_ports_count),
        float(vt_reputation),
    ]