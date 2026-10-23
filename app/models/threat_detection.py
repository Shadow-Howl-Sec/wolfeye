from __future__ import annotations

import json
from datetime import datetime, timezone

from app import db


class ThreatDetection(db.Model):
    """Persisted result of metadata-only packet/flow analysis."""

    __tablename__ = "threat_detection"
    __allow_unmapped__ = True

    id: int = db.Column(db.Integer, primary_key=True)
    flow_record_id: int | None = db.Column(db.Integer, db.ForeignKey("flow_record.id"), nullable=True)
    alert_id: int | None = db.Column(db.Integer, db.ForeignKey("alert.id"), nullable=True)
    source_ip: str = db.Column(db.String(128), nullable=False)
    destination_ip: str | None = db.Column(db.String(128), nullable=True)
    protocol: str = db.Column(db.String(16), nullable=False)
    threat_type: str = db.Column(db.String(64), nullable=False)
    severity: str = db.Column(db.String(16), nullable=False)
    score: float = db.Column(db.Float, nullable=False)
    indicators: str = db.Column(db.Text, nullable=False, default="[]")
    decision: str = db.Column(db.String(32), nullable=False, default="allowed")
    blocked: bool = db.Column(db.Boolean, nullable=False, default=False)
    created_at: datetime = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict:
        try:
            indicators = json.loads(self.indicators or "[]")
        except (TypeError, ValueError):
            indicators = []
        return {
            "id": self.id,
            "flow_record_id": self.flow_record_id,
            "alert_id": self.alert_id,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "score": self.score,
            "indicators": indicators,
            "decision": self.decision,
            "blocked": self.blocked,
            "created_at": self.created_at.isoformat(),
        }
