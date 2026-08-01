"""
app/models/audit_log.py
------------------------
AuditLog — immutable record of every analyst action taken on an IOC.

Strengthens the "response" story: proves the platform has a basic SOAR-style
action loop with a traceable audit trail.

Schema:
    AuditLog(id, ioc_id→IOC, action, performed_by, timestamp, detail)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from app import db

if TYPE_CHECKING:
    from app.models.ioc import IOC


class AuditAction:
    """Canonical action names written to the audit log."""
    INVESTIGATED = "mark_investigated"
    WATCHLISTED = "add_to_watchlist"
    UNWATCHLISTED = "remove_from_watchlist"
    EXPORTED = "exported"
    ALERT_CREATED = "alert_created"
    ALERT_RESOLVED = "alert_resolved"
    STATUS_CHANGED = "status_changed"
    INGESTED = "ingested"
    ENRICHED = "enriched"
    SCORED = "anomaly_scored"


class AuditLog(db.Model):
    """
    Append-only record of actions performed on an IOC.

    Note: rows are never updated or deleted — the table is an audit trail.
    """

    __tablename__ = "audit_log"

    id: int = db.Column(db.Integer, primary_key=True)
    ioc_id: int = db.Column(
        db.Integer, db.ForeignKey("ioc.id", ondelete="CASCADE"), nullable=False
    )

    # The canonical action name (see AuditAction constants)
    action: str = db.Column(db.String(64), nullable=False)

    # Username of the actor (system or analyst)
    performed_by: str = db.Column(db.String(128), nullable=False, default="system")

    # Optional extra context (e.g., previous → new status)
    detail: str | None = db.Column(db.Text, nullable=True)

    timestamp: datetime = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    # Relationship back to IOC
    ioc: "IOC" = db.relationship("IOC", back_populates="audit_logs")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ioc_id": self.ioc_id,
            "action": self.action,
            "performed_by": self.performed_by,
            "detail": self.detail,
            "timestamp": self.timestamp.isoformat(),
        }

    def __repr__(self) -> str:
        return (
            f"<AuditLog ioc_id={self.ioc_id} action={self.action!r} by={self.performed_by!r}>"
        )
