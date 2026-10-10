from __future__ import annotations

from datetime import datetime, timezone

from app import db


class Node(db.Model):
    """Registered data-plane node."""

    __tablename__ = "node"
    __allow_unmapped__ = True

    id: int = db.Column(db.Integer, primary_key=True)
    name: str = db.Column(db.String(128), nullable=False, unique=True)
    mode: str = db.Column(db.String(32), nullable=False, default="gateway")
    token_hash: str = db.Column(db.String(255), nullable=False)
    last_seen: datetime | None = db.Column(db.DateTime(timezone=True), nullable=True)
    version: str = db.Column(db.String(64), nullable=False, default="unknown")
    created_at: datetime = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    active: bool = db.Column(db.Boolean, nullable=False, default=True)

    audit_logs: list["AuditLog"] = db.relationship("AuditLog", back_populates="node")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "mode": self.mode,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "version": self.version,
            "created_at": self.created_at.isoformat(),
            "active": self.active,
        }
