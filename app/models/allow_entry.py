from __future__ import annotations

from datetime import datetime, timezone

from app import db


class AllowEntry(db.Model):
    """Allowlist entry."""

    __tablename__ = "allow_entry"
    __allow_unmapped__ = True

    id: int = db.Column(db.Integer, primary_key=True)
    kind: str = db.Column(db.String(32), nullable=False)
    value: str = db.Column(db.String(512), nullable=False)
    reason: str = db.Column(db.String(255), nullable=False, default="")
    created_by: str = db.Column(db.String(128), nullable=False, default="system")
    created_at: datetime = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    expires_at: datetime | None = db.Column(db.DateTime(timezone=True), nullable=True)

    __table_args__ = (
        db.Index("ix_allow_entry_value_expires", "value", "expires_at"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "value": self.value,
            "reason": self.reason,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }
