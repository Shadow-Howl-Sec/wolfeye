"""
app/models/ioc.py
------------------
Indicator of Compromise (IOC) — the central entity of the platform.

Schema:
    IOC(id, value, type, source, first_seen, created_at, status, watchlisted)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from app import db

if TYPE_CHECKING:
    from app.models.enrichment import Enrichment
    from app.models.alert import Alert
    from app.models.audit_log import AuditLog


class IOCStatus:
    """Allowed values for IOC.status."""
    NEW = "new"
    INVESTIGATED = "investigated"
    WATCHLISTED = "watchlisted"
    CLOSED = "closed"


class IOCType:
    """Known indicator types."""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"


class ScoreMethod:
    """Score sources used to judge IOC risk."""

    UNSET = "unset"
    HEURISTIC = "heuristic"
    ISOLATION_FOREST = "isolation_forest"


class IOC(db.Model):
    """
    Represents a single Indicator of Compromise ingested from a threat feed.

    Relationships:
        enrichment  — one-to-one (lazy loaded)
        alerts      — one-to-many
        audit_logs  — one-to-many
    """

    __tablename__ = "ioc"
    __allow_unmapped__ = True

    # Primary key
    id: int = db.Column(db.Integer, primary_key=True)

    # Core fields
    value: str = db.Column(db.String(2048), nullable=False)
    type: str = db.Column(db.String(32), nullable=False)  # ip | domain | url | hash | email
    source: str = db.Column(db.String(128), nullable=False)  # urlhaus | threatfox | manual

    # Timestamps
    first_seen: datetime = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    created_at: datetime = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    # Analyst workflow state
    status: str = db.Column(db.String(32), nullable=False, default=IOCStatus.NEW)
    watchlisted: bool = db.Column(db.Boolean, nullable=False, default=False)

    # The production risk score is the heuristic score from the live threat model.
    # The Isolation Forest score is stored separately as a secondary signal.
    risk_score: float | None = db.Column(db.Float, nullable=True)
    anomaly_score: float | None = db.Column(db.Float, nullable=True)
    score_method: str = db.Column(db.String(32), nullable=False, default=ScoreMethod.UNSET)

    # Relationships
    enrichment: "Enrichment" = db.relationship(
        "Enrichment", back_populates="ioc", uselist=False, cascade="all, delete-orphan"
    )
    alerts: list["Alert"] = db.relationship(
        "Alert", back_populates="ioc", cascade="all, delete-orphan"
    )
    audit_logs: list["AuditLog"] = db.relationship(
        "AuditLog", back_populates="ioc", cascade="all, delete-orphan"
    )
    intel_context: list["IntelContext"] = db.relationship(
        "IntelContext", back_populates="ioc", cascade="all, delete-orphan"
    )

    # Unique constraint: same indicator from same source is deduplicated
    __table_args__ = (
        db.UniqueConstraint("value", "type", name="uq_ioc_value_type"),
    )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def normalize_score_fields(self) -> None:
        """Backfill legacy rows that only stored the heuristic score in anomaly_score."""
        if self.score_method == ScoreMethod.UNSET and self.risk_score is None and self.anomaly_score is not None:
            self.risk_score = float(self.anomaly_score)
            self.score_method = ScoreMethod.HEURISTIC

    def to_dict(self, include_enrichment: bool = False) -> dict:
        self.normalize_score_fields()
        data = {
            "id": self.id,
            "value": self.value,
            "type": self.type,
            "source": self.source,
            "first_seen": self.first_seen.isoformat(),
            "created_at": self.created_at.isoformat(),
            "status": self.status,
            "watchlisted": self.watchlisted,
            "risk_score": self.risk_score,
            "anomaly_score": self.anomaly_score,
            "score_method": self.score_method,
        }
        if include_enrichment and self.enrichment:
            data["enrichment"] = self.enrichment.to_dict()
            data["intel_context"] = [item.to_dict() for item in self.intel_context]
        return data

    def __repr__(self) -> str:
        return f"<IOC {self.type}:{self.value!r} [{self.status}]>"
