"""
app/models/enrichment.py
-------------------------
Enrichment data for an IOC — one-to-one relationship.

Stores both parsed fields (for queries/charts) and the raw JSON
responses from each API (for reprocessing later).

Schema:
    Enrichment(id, ioc_id→IOC, vt_reputation, vt_detections,
               abuseipdb_score, abuseipdb_country, abuseipdb_isp,
               shodan_ports, shodan_org, country,
               raw_vt_json, raw_abuseipdb_json, raw_shodan_json,
               last_updated)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from app import db

if TYPE_CHECKING:
    from app.models.ioc import IOC


class Enrichment(db.Model):
    """
    Enrichment data linked to a single IOC.

    All API-specific raw responses are stored as TEXT (JSON string) so we can
    reprocess them without hitting rate limits again.
    """

    __tablename__ = "enrichment"

    id: int = db.Column(db.Integer, primary_key=True)
    ioc_id: int = db.Column(
        db.Integer, db.ForeignKey("ioc.id", ondelete="CASCADE"), nullable=False, unique=True
    )

    # VirusTotal
    vt_reputation: int | None = db.Column(db.Integer, nullable=True)
    vt_detections: int | None = db.Column(db.Integer, nullable=True)        # malicious count
    vt_total_engines: int | None = db.Column(db.Integer, nullable=True)     # total engine count

    # AbuseIPDB
    abuseipdb_score: int | None = db.Column(db.Integer, nullable=True)      # 0-100 confidence
    abuseipdb_country: str | None = db.Column(db.String(8), nullable=True)  # ISO country code
    abuseipdb_isp: str | None = db.Column(db.String(256), nullable=True)

    # Shodan
    shodan_ports: str | None = db.Column(db.Text, nullable=True)  # JSON list e.g. "[22, 80, 443]"
    shodan_org: str | None = db.Column(db.String(256), nullable=True)
    shodan_country: str | None = db.Column(db.String(8), nullable=True)

    # Unified country (best available: AbuseIPDB → Shodan → None)
    country: str | None = db.Column(db.String(8), nullable=True)

    # Raw JSON responses (stored as text for reprocessing)
    raw_vt_json: str | None = db.Column(db.Text, nullable=True)
    raw_abuseipdb_json: str | None = db.Column(db.Text, nullable=True)
    raw_shodan_json: str | None = db.Column(db.Text, nullable=True)

    last_updated: datetime = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationship back to IOC
    ioc: "IOC" = db.relationship("IOC", back_populates="enrichment")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def shodan_ports_list(self) -> list[int]:
        """Return Shodan ports as a Python list."""
        if self.shodan_ports:
            try:
                return json.loads(self.shodan_ports)
            except (json.JSONDecodeError, TypeError):
                return []
        return []

    def to_dict(self) -> dict:
        return {
            "vt_reputation": self.vt_reputation,
            "vt_detections": self.vt_detections,
            "vt_total_engines": self.vt_total_engines,
            "abuseipdb_score": self.abuseipdb_score,
            "abuseipdb_country": self.abuseipdb_country,
            "abuseipdb_isp": self.abuseipdb_isp,
            "shodan_ports": self.shodan_ports_list,
            "shodan_org": self.shodan_org,
            "country": self.country,
            "last_updated": self.last_updated.isoformat(),
        }

    def __repr__(self) -> str:
        return f"<Enrichment ioc_id={self.ioc_id} country={self.country!r}>"
