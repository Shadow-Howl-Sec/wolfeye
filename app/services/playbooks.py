"""
app/services/playbooks.py
--------------------------
Analyst response playbook actions — every action writes an AuditLog entry.

Available actions:
    * mark_investigated(ioc_id, performed_by)
    * add_to_watchlist(ioc_id, performed_by)
    * remove_from_watchlist(ioc_id, performed_by)
    * export_iocs(ioc_ids, fmt)            → CSV or JSON string
    * resolve_alert(alert_id, performed_by, notes)
"""

from __future__ import annotations

import csv
import io
import json
import logging
from typing import Literal

from app import db
from app.models.ioc import IOC, IOCStatus
from app.models.alert import Alert, AlertStatus
from app.models.audit_log import AuditLog, AuditAction

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _get_ioc_or_raise(ioc_id: int) -> IOC:
    ioc = IOC.query.get(ioc_id)
    if ioc is None:
        raise ValueError(f"IOC with id={ioc_id} not found")
    return ioc


def _write_audit(ioc_id: int, action: str, performed_by: str, detail: str | None = None) -> None:
    log = AuditLog(
        ioc_id=ioc_id,
        action=action,
        performed_by=performed_by,
        detail=detail,
    )
    db.session.add(log)


# ---------------------------------------------------------------------------
# Playbook actions
# ---------------------------------------------------------------------------

def mark_investigated(ioc_id: int, performed_by: str = "analyst") -> IOC:
    """
    Mark an IOC as investigated and update its status.

    Args:
        ioc_id:       ID of the IOC to update.
        performed_by: Username of the analyst performing the action.

    Returns:
        Updated IOC object.
    """
    ioc = _get_ioc_or_raise(ioc_id)
    prev_status = ioc.status
    ioc.status = IOCStatus.INVESTIGATED
    _write_audit(
        ioc_id=ioc_id,
        action=AuditAction.INVESTIGATED,
        performed_by=performed_by,
        detail=f"{prev_status} → {IOCStatus.INVESTIGATED}",
    )
    db.session.commit()
    logger.info("IOC %d marked as investigated by %r", ioc_id, performed_by)
    return ioc


def add_to_watchlist(ioc_id: int, performed_by: str = "analyst") -> IOC:
    """
    Add an IOC to the watchlist.

    Args:
        ioc_id:       ID of the IOC.
        performed_by: Username performing the action.

    Returns:
        Updated IOC object.
    """
    ioc = _get_ioc_or_raise(ioc_id)
    ioc.watchlisted = True
    ioc.status = IOCStatus.WATCHLISTED
    _write_audit(
        ioc_id=ioc_id,
        action=AuditAction.WATCHLISTED,
        performed_by=performed_by,
        detail="added to watchlist",
    )
    db.session.commit()
    logger.info("IOC %d added to watchlist by %r", ioc_id, performed_by)
    return ioc


def remove_from_watchlist(ioc_id: int, performed_by: str = "analyst") -> IOC:
    """
    Remove an IOC from the watchlist.

    Args:
        ioc_id:       ID of the IOC.
        performed_by: Username performing the action.

    Returns:
        Updated IOC object.
    """
    ioc = _get_ioc_or_raise(ioc_id)
    ioc.watchlisted = False
    if ioc.status == IOCStatus.WATCHLISTED:
        ioc.status = IOCStatus.NEW
    _write_audit(
        ioc_id=ioc_id,
        action=AuditAction.UNWATCHLISTED,
        performed_by=performed_by,
        detail="removed from watchlist",
    )
    db.session.commit()
    return ioc


def export_iocs(
    ioc_ids: list[int] | None = None,
    fmt: Literal["csv", "json"] = "csv",
) -> tuple[str, str]:
    """
    Export IOCs as CSV or JSON.

    Args:
        ioc_ids: List of IOC IDs to export. If None, exports all.
        fmt:     Output format — ``"csv"`` or ``"json"``.

    Returns:
        Tuple of (content_string, mimetype).
    """
    query = IOC.query
    if ioc_ids:
        query = query.filter(IOC.id.in_(ioc_ids))
    iocs = query.all()

    rows = [ioc.to_dict(include_enrichment=True) for ioc in iocs]

    if fmt == "json":
        return json.dumps(rows, indent=2, default=str), "application/json"

    # CSV output
    if not rows:
        return "", "text/csv"

    output = io.StringIO()
    # Flatten enrichment into top-level keys for CSV readability
    flat_rows = []
    for row in rows:
        enrichment = row.pop("enrichment", {}) or {}
        flat_rows.append({**row, **{f"enrich_{k}": v for k, v in enrichment.items()}})

    writer = csv.DictWriter(output, fieldnames=flat_rows[0].keys(), extrasaction="ignore")
    writer.writeheader()
    writer.writerows(flat_rows)
    return output.getvalue(), "text/csv"


def resolve_alert(
    alert_id: int,
    performed_by: str = "analyst",
    notes: str | None = None,
) -> Alert:
    """
    Resolve an open alert.

    Args:
        alert_id:     ID of the Alert to resolve.
        performed_by: Username performing the action.
        notes:        Optional analyst notes.

    Returns:
        Updated Alert object.
    """
    alert = Alert.query.get(alert_id)
    if alert is None:
        raise ValueError(f"Alert with id={alert_id} not found")

    alert.status = AlertStatus.RESOLVED
    if notes:
        alert.notes = notes

    _write_audit(
        ioc_id=alert.ioc_id,
        action=AuditAction.ALERT_RESOLVED,
        performed_by=performed_by,
        detail=f"Alert {alert_id} resolved. Notes: {notes or '—'}",
    )
    db.session.commit()
    logger.info("Alert %d resolved by %r", alert_id, performed_by)
    return alert
