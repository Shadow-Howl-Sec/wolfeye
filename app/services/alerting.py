"""
app/services/alerting.py
-------------------------
Converts risk scores into Alert records and optionally sends email
notifications for high-severity alerts.

Severity banding:
    score >= 0.90  → Critical
    score >= 0.80  → High
    score >= 0.70  → Medium
    score >= 0.60  → Low
    score <  0.60  → no alert generated
"""

from __future__ import annotations

import logging
import smtplib
from datetime import datetime, timezone
from email.mime.text import MIMEText
from typing import Any

from app import db
from app.models.ioc import IOC
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.audit_log import AuditLog, AuditAction

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Alert creation
# ---------------------------------------------------------------------------

def create_alert_if_needed(
    ioc: IOC,
    score: float,
    threshold: float = 0.60,
) -> Alert | None:
    """Create an alert from the IOC's risk score when it crosses the configured threshold."""
    risk_score = float(score if score is not None else 0.0)
    if risk_score < threshold:
        return None

    existing = Alert.query.filter_by(ioc_id=ioc.id, status=AlertStatus.OPEN).first()
    if existing:
        logger.debug("IOC %d already has an open alert, skipping", ioc.id)
        return None

    severity = AlertSeverity.from_score(risk_score)
    alert = Alert(
        ioc_id=ioc.id,
        risk_score=risk_score,
        anomaly_score=getattr(ioc, "anomaly_score", risk_score) or risk_score,
        severity=severity,
        status=AlertStatus.OPEN,
        created_at=datetime.now(timezone.utc),
    )
    db.session.add(alert)

    log = AuditLog(
        ioc_id=ioc.id,
        action=AuditAction.ALERT_CREATED,
        performed_by="system",
        detail=f"score={score:.4f} severity={severity}",
    )
    db.session.add(log)
    db.session.commit()

    logger.info(
        "Alert created: IOC %d (%s) score=%.4f severity=%s",
        ioc.id, ioc.value, score, severity,
    )
    return alert


# ---------------------------------------------------------------------------
# Bulk alerting run (called by scheduler / after scoring)
# ---------------------------------------------------------------------------

def run_alerting(app) -> dict[str, Any]:
    """
    Scan all scored IOCs and create alerts for those above threshold.

    Args:
        app: Flask application instance.

    Returns:
        Summary dict with counts.
    """
    with app.app_context():
        threshold: float = app.config.get("ALERT_MIN_SCORE", app.config.get("ANOMALY_ALERT_THRESHOLD", 0.60))

        scored_iocs = IOC.query.filter(IOC.risk_score.isnot(None)).all()
        created = 0
        skipped = 0

        for ioc in scored_iocs:
            alert = create_alert_if_needed(ioc, ioc.risk_score, threshold)
            if alert:
                created += 1
                if alert.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL):
                    _send_email_alert(alert, ioc, app.config)
            else:
                skipped += 1

        summary = {"checked": len(scored_iocs), "alerts_created": created, "skipped": skipped}
        logger.info("Alerting run: %s", summary)
        return summary


# ---------------------------------------------------------------------------
# Email notification
# ---------------------------------------------------------------------------

def _send_email_alert(alert: Alert, ioc: IOC, config: dict) -> bool:
    """
    Send an email notification for a high/critical alert.

    Silently returns False if SMTP credentials are not configured.
    """
    smtp_user = config.get("SMTP_USER", "")
    smtp_pass = config.get("SMTP_PASSWORD", "")
    to_addr = config.get("ALERT_EMAIL_TO", "")

    if not all([smtp_user, smtp_pass, to_addr]):
        return False  # email not configured

    subject = f"[WolfEye] {alert.severity.upper()} Alert — {ioc.type.upper()}: {ioc.value[:80]}"
    body = (
        f"WolfEye has detected a {alert.severity.upper()} severity threat:\n\n"
        f"  Indicator : {ioc.value}\n"
        f"  Type      : {ioc.type}\n"
        f"  Source    : {ioc.source}\n"
        f"  Risk score: {alert.risk_score if alert.risk_score is not None else alert.anomaly_score:.4f}\n"
        f"  Severity  : {alert.severity}\n"
        f"  Detected  : {alert.created_at.isoformat()}\n\n"
        f"Log in to the WolfEye dashboard to investigate."
    )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = to_addr

    try:
        with smtplib.SMTP(config.get("SMTP_HOST", "smtp.gmail.com"), int(config.get("SMTP_PORT", 587))) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(smtp_user, smtp_pass)
            smtp.sendmail(smtp_user, [to_addr], msg.as_string())
        logger.info("Alert email sent to %s for IOC %d", to_addr, ioc.id)
        return True
    except Exception as exc:
        logger.error("Failed to send alert email: %s", exc)
        return False
