from __future__ import annotations

from datetime import datetime, timezone

from app import db


class BlockEntry(db.Model):
    """Static or dynamic blocklist entry."""

    __tablename__ = "block_entry"
    __allow_unmapped__ = True

    id: int = db.Column(db.Integer, primary_key=True)
    kind: str = db.Column(db.String(32), nullable=False)
    value: str = db.Column(db.String(512), nullable=False)
    reason: str = db.Column(db.String(255), nullable=False, default="")
    source: str = db.Column(db.String(32), nullable=False, default="expert")
    created_by: str = db.Column(db.String(128), nullable=False, default="system")
    created_at: datetime = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    expires_at: datetime | None = db.Column(db.DateTime(timezone=True), nullable=True)
    active: bool = db.Column(db.Boolean, nullable=False, default=True)
    related_alert_id: int | None = db.Column(db.Integer, nullable=True)

    __table_args__ = (
        db.Index("ix_block_entry_value_active_expires", "value", "active", "expires_at"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "value": self.value,
            "reason": self.reason,
            "source": self.source,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "active": self.active,
            "related_alert_id": self.related_alert_id,
        }
