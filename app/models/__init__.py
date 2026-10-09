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

__all__ = ["IOC", "Enrichment", "Alert", "AuditLog", "User", "IntelContext"]
