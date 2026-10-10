from __future__ import annotations

from datetime import datetime, timezone

from app import db


class EventLog(db.Model):
    """Short-retention event log for flagged or sampled requests."""

    __tablename__ = "event_log"
    __allow_unmapped__ = True

    id: int = db.Column(db.Integer, primary_key=True)
    node_id: int | None = db.Column(db.Integer, nullable=True)
    event_type: str = db.Column(db.String(32), nullable=False, default="request")
    source_ip: str | None = db.Column(db.String(128), nullable=True)
    destination: str | None = db.Column(db.String(255), nullable=True)
    payload: str = db.Column(db.Text, nullable=False, default="{}")
    created_at: datetime = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        db.Index("ix_event_log_created_at", "created_at"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "node_id": self.node_id,
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "destination": self.destination,
            "payload": self.payload,
            "created_at": self.created_at.isoformat(),
        }
