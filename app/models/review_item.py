from __future__ import annotations

import json
from datetime import datetime, timezone

from app import db


class ReviewItem(db.Model):
    """Review queue item generated from an alert."""

    __tablename__ = "review_item"
    __allow_unmapped__ = True

    id: int = db.Column(db.Integer, primary_key=True)
    alert_id: int = db.Column(db.Integer, db.ForeignKey("alert.id", ondelete="CASCADE"), nullable=False)
    subject: str = db.Column(db.String(255), nullable=False)
    evidence_json: str = db.Column(db.Text, nullable=False, default="{}")
    status: str = db.Column(db.String(32), nullable=False, default="open")
    decided_by: str | None = db.Column(db.String(128), nullable=True)
    decided_at: datetime | None = db.Column(db.DateTime(timezone=True), nullable=True)
    decision_note: str | None = db.Column(db.Text, nullable=True)

    created_at: datetime = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    alert: "Alert" = db.relationship("Alert", backref="review_items")

    def to_dict(self) -> dict:
        payload = {}
        if self.evidence_json:
            try:
                payload = json.loads(self.evidence_json)
            except (TypeError, ValueError):
                payload = {"raw": self.evidence_json}
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "subject": self.subject,
            "evidence": payload,
            "status": self.status,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "decision_note": self.decision_note,
            "created_at": self.created_at.isoformat(),
        }
