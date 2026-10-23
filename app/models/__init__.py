"""
app/models/__init__.py
-----------------------
Import all models here so SQLAlchemy's metadata is populated before
``db.create_all()`` is called in the app factory.
"""

from app.models.ioc import IOC  # noqa: F401
from app.models.enrichment import Enrichment  # noqa: F401
from app.models.alert import Alert  # noqa: F401
from app.models.audit_log import AuditLog  # noqa: F401
from app.models.user import User  # noqa: F401
from app.models.intel_context import IntelContext  # noqa: F401
from app.models.node import Node  # noqa: F401
from app.models.block_entry import BlockEntry  # noqa: F401
from app.models.allow_entry import AllowEntry  # noqa: F401
from app.models.review_item import ReviewItem  # noqa: F401
from app.models.flow_record import FlowRecord  # noqa: F401
from app.models.event_log import EventLog  # noqa: F401
from app.models.config_setting import ConfigSetting  # noqa: F401
from app.models.threat_detection import ThreatDetection  # noqa: F401

__all__ = [
    "IOC",
    "Enrichment",
    "Alert",
    "AuditLog",
    "User",
    "IntelContext",
    "Node",
    "BlockEntry",
    "AllowEntry",
    "ReviewItem",
    "FlowRecord",
    "EventLog",
    "ConfigSetting",
    "ThreatDetection",
]
