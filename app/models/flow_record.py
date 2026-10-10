from __future__ import annotations

import json
from datetime import datetime, timezone

from app import db


class FlowRecord(db.Model):
    """Captured network flow record."""

    __tablename__ = "flow_record"
    __allow_unmapped__ = True

    id: int = db.Column(db.Integer, primary_key=True)
    flow_id: str = db.Column(db.String(255), nullable=False, index=True)
    node_id: int | None = db.Column(db.Integer, nullable=True)
    src_ip: str | None = db.Column(db.String(128), nullable=True)
    dst_ip: str | None = db.Column(db.String(128), nullable=True)
    ports: str | None = db.Column(db.String(128), nullable=True)
    protocol: str | None = db.Column(db.String(32), nullable=True)
    features: str = db.Column(db.Text, nullable=False, default="{}")
    cnn_lstm_class: str | None = db.Column(db.String(64), nullable=True)
    cnn_lstm_confidence: float | None = db.Column(db.Float, nullable=True)
    created_at: datetime = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict:
        payload = {}
        if self.features:
            try:
                payload = json.loads(self.features)
            except (TypeError, ValueError):
                payload = {"raw": self.features}
        return {
            "id": self.id,
            "flow_id": self.flow_id,
            "node_id": self.node_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "ports": self.ports,
            "protocol": self.protocol,
            "features": payload,
            "cnn_lstm_class": self.cnn_lstm_class,
            "cnn_lstm_confidence": self.cnn_lstm_confidence,
            "created_at": self.created_at.isoformat(),
        }
