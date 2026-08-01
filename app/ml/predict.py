"""
app/ml/predict.py
------------------
Interface between the backend pipeline and Member B's Isolation Forest model.

This module defines the CONTRACT that Member B's model must satisfy.
The backend calls ``predict_anomaly_score()`` and ``score_pending_iocs()``
— Member B only needs to implement the model loading / feature extraction
inside this file (or drop a trained model at MODEL_PATH).

Current state:
    If no trained model exists (MODEL_PATH not found), the module falls back
    to a deterministic heuristic score based on available enrichment data so
    the rest of the pipeline keeps working end-to-end without a trained model.

Model file:
    Place the trained scikit-learn model (pickled with joblib) at:
        app/ml/model.joblib

Feature vector (agreed interface with Member B):
    [vt_detections, vt_reputation, abuseipdb_score, num_shodan_ports]
    All values are floats; missing → 0.0.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).parent / "model.joblib"

# ---------------------------------------------------------------------------
# Model loading (lazy singleton)
# ---------------------------------------------------------------------------

_model = None
_model_loaded: bool = False


def _load_model():
    """Load the trained Isolation Forest model from disk (once)."""
    global _model, _model_loaded
    if _model_loaded:
        return _model

    _model_loaded = True
    if not MODEL_PATH.exists():
        logger.warning(
            "No trained model found at %s — using heuristic fallback scorer", MODEL_PATH
        )
        return None

    try:
        import joblib  # type: ignore
        _model = joblib.load(MODEL_PATH)
        logger.info("Isolation Forest model loaded from %s", MODEL_PATH)
    except Exception as exc:
        logger.error("Failed to load model: %s — falling back to heuristic", exc)
        _model = None

    return _model


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def _extract_features(ioc) -> list[float]:
    """
    Build a numeric feature vector from an IOC + its Enrichment.

    Agreed feature order (Member B must use the same order when training):
        0: vt_detections       (0 if missing)
        1: vt_reputation       (0 if missing)
        2: abuseipdb_score     (0 if missing)
        3: num_shodan_ports    (0 if missing)

    Args:
        ioc: IOC ORM object (enrichment relationship must be loaded).

    Returns:
        Feature list as floats.
    """
    enr = ioc.enrichment
    if enr is None:
        return [0.0, 0.0, 0.0, 0.0]

    return [
        float(enr.vt_detections or 0),
        float(enr.vt_reputation or 0),
        float(enr.abuseipdb_score or 0),
        float(len(enr.shodan_ports_list)),
    ]


# ---------------------------------------------------------------------------
# Heuristic fallback (used when model.joblib is absent)
# ---------------------------------------------------------------------------

def _heuristic_score(features: list[float]) -> float:
    """
    Simple rule-based score — a placeholder until Member B trains the model.

    Score is a weighted combination of enrichment signals, clamped to [0, 1].
    """
    vt_det, vt_rep, abuse, ports = features

    score = 0.0
    # VirusTotal detections: up to 0.4 weight
    score += min(vt_det / 10.0, 0.4)
    # AbuseIPDB confidence: up to 0.4 weight
    score += (abuse / 100.0) * 0.4
    # Negative reputation: up to 0.1 weight
    score += min(max(-vt_rep, 0) / 100.0, 0.1)
    # Open ports (many ports = more exposure): up to 0.1 weight
    score += min(ports / 50.0, 0.1)

    return round(min(score, 1.0), 4)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def predict_anomaly_score(ioc) -> float:
    """
    Return an anomaly score in [0, 1] for a single IOC.

    Uses the trained Isolation Forest model if available; otherwise falls
    back to the heuristic scorer.

    Args:
        ioc: IOC ORM object with enrichment loaded.

    Returns:
        Float in [0.0, 1.0] — higher = more anomalous / suspicious.
    """
    features = _extract_features(ioc)
    model = _load_model()

    if model is not None:
        try:
            import numpy as np
            arr = np.array(features).reshape(1, -1)
            # IsolationForest.decision_function: negative = more anomalous
            raw = model.decision_function(arr)[0]
            # Normalise: typical range is roughly [-0.5, 0.5] → [0, 1]
            score = float(1.0 - (raw + 0.5))
            return round(max(0.0, min(score, 1.0)), 4)
        except Exception as exc:
            logger.error("Model prediction failed: %s — using heuristic", exc)

    return _heuristic_score(features)


def score_pending_iocs(app) -> dict[str, Any]:
    """
    Score all IOCs that have enrichment data but no anomaly score yet.

    Args:
        app: Flask application instance (used for app context).

    Returns:
        Summary dict with counts.
    """
    from app import db
    from app.models.ioc import IOC
    from app.models.enrichment import Enrichment
    from app.models.audit_log import AuditLog, AuditAction

    unscored = (
        IOC.query
        .join(Enrichment)
        .filter(IOC.anomaly_score.is_(None))
        .all()
    )

    scored = 0
    for ioc in unscored:
        try:
            score = predict_anomaly_score(ioc)
            ioc.anomaly_score = score

            log = AuditLog(
                ioc_id=ioc.id,
                action=AuditAction.SCORED,
                performed_by="system",
                detail=f"anomaly_score={score}",
            )
            db.session.add(log)
            scored += 1
        except Exception as exc:
            logger.error("Scoring failed for IOC %d: %s", ioc.id, exc)

    db.session.commit()
    logger.info("Scoring complete: %d IOCs scored", scored)
    return {"unscored_found": len(unscored), "scored": scored}
