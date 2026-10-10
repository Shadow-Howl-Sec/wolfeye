from __future__ import annotations

from datetime import datetime, timezone

from app import db


class ConfigSetting(db.Model):
    """Runtime configuration key/value entries."""

    __tablename__ = "config_setting"
    __allow_unmapped__ = True

    id: int = db.Column(db.Integer, primary_key=True)
    key: str = db.Column(db.String(128), nullable=False, unique=True, index=True)
    value: str = db.Column(db.String(1024), nullable=False, default="")
    updated_at: datetime = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "key": self.key,
            "value": self.value,
            "updated_at": self.updated_at.isoformat(),
        }
