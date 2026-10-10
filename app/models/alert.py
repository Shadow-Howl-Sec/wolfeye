"""
app/models/alert.py
--------------------
Alert — generated when an IOC's risk score crosses a threshold.

Schema:
    Alert(id, ioc_id→IOC, risk_score, anomaly_score, severity, status, created_at)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from app import db

if TYPE_CHECKING:
    from app.models.ioc import IOC


class AlertSeverity:
    """Severity banding based on the production risk score."""

    LOW = "low"           # 0.60 – 0.69
    MEDIUM = "medium"     # 0.70 – 0.79
    HIGH = "high"         # 0.80 – 0.89
    CRITICAL = "critical" # 0.90+

    @staticmethod
    def from_score(
        score: float,
        low: float = 0.60,
        medium: float = 0.70,
        high: float = 0.80,
        critical: float = 0.90,
    ) -> str:
        if score is None:
            return AlertSeverity.LOW
        if score >= critical:
            return AlertSeverity.CRITICAL
        if score >= high:
            return AlertSeverity.HIGH
        if score >= medium:
            return AlertSeverity.MEDIUM
        if score >= low:
            return AlertSeverity.LOW
        return AlertSeverity.LOW


class AlertStatus:
    """Lifecycle states for an alert."""
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Alert(db.Model):
    """
    Alert record created by the alerting service when an IOC's risk score
    exceeds the configured threshold.
    """

    __tablename__ = "alert"
    __allow_unmapped__ = True

    id: int = db.Column(db.Integer, primary_key=True)
    ioc_id: int = db.Column(
        db.Integer, db.ForeignKey("ioc.id", ondelete="CASCADE"), nullable=False
    )

    # Score snapshot at the time the alert was created. The production risk score
    # is the primary signal for alert severity; anomaly_score remains a secondary model signal.
    risk_score: float | None = db.Column(db.Float, nullable=True)
    anomaly_score: float = db.Column(db.Float, nullable=False, default=0.0)

    # Derived from the risk score via AlertSeverity.from_score()
    severity: str = db.Column(db.String(16), nullable=False, default=AlertSeverity.LOW)

    # Workflow state
    status: str = db.Column(db.String(32), nullable=False, default=AlertStatus.OPEN)

    # Timestamps
    created_at: datetime = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Optional analyst notes
    notes: str | None = db.Column(db.Text, nullable=True)

    # Relationship back to IOC
    ioc: "IOC" = db.relationship("IOC", back_populates="alerts")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def to_dict(self, include_ioc: bool = False) -> dict:
        data = {
            "id": self.id,
            "ioc_id": self.ioc_id,
            "risk_score": round(self.risk_score, 4) if self.risk_score is not None else None,
            "anomaly_score": round(self.anomaly_score, 4) if self.anomaly_score is not None else None,
            "severity": self.severity,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "notes": self.notes,
        }
        if include_ioc and self.ioc:
            data["ioc"] = self.ioc.to_dict()
        return data

    def __repr__(self) -> str:
        return f"<Alert ioc_id={self.ioc_id} severity={self.severity!r} status={self.status!r}>"
