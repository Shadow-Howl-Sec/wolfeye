"""Community and graph intelligence attached to an IOC."""

from __future__ import annotations

from datetime import datetime, timezone

from app import db


class IntelContext(db.Model):
    __tablename__ = "intel_context"
    __allow_unmapped__ = True

    id: int = db.Column(db.Integer, primary_key=True)
    ioc_id: int = db.Column(
        db.Integer, db.ForeignKey("ioc.id", ondelete="CASCADE"), nullable=False
    )
    provider: str = db.Column(db.String(32), nullable=False)
    external_id: str = db.Column(db.String(256), nullable=True)
    context_json: str = db.Column(db.Text, nullable=False)
    created_at: datetime = db.Column(
        db.DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    ioc = db.relationship("IOC", back_populates="intel_context")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "provider": self.provider,
            "external_id": self.external_id,
            "context": self.context_json,
            "created_at": self.created_at.isoformat(),
        }
