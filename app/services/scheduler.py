"""
app/services/scheduler.py
--------------------------
APScheduler setup for background jobs:

    1. Ingestion job  — pulls IOCs from URLhaus + ThreatFox
    2. Enrichment job — enriches unenriched/stale IOCs
    3. Scoring job    — runs Member B's model and creates alerts

Jobs run inside the Flask application context so they can access
db, config, and all models safely.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)

# Singleton scheduler instance — shared across the process
_scheduler: BackgroundScheduler | None = None

# Records of the last run times and results for /api/system/health
_job_status: dict[str, dict] = {
    "ingestion": {"last_run": None, "last_result": None, "last_error": None},
    "enrichment": {"last_run": None, "last_result": None, "last_error": None},
    "scoring": {"last_run": None, "last_result": None, "last_error": None},
}


def get_job_status() -> dict:
    """Return the current health status of all scheduled jobs."""
    return {
        job: {
            **info,
            "last_run": info["last_run"].isoformat() if info["last_run"] else None,
        }
        for job, info in _job_status.items()
    }


# ---------------------------------------------------------------------------
# Job functions (wrapped to capture errors into _job_status)
# ---------------------------------------------------------------------------

def _ingestion_job(app) -> None:
    try:
        from app.services.ingestion import run_ingestion
        result = run_ingestion(app)
        _job_status["ingestion"]["last_run"] = datetime.now(timezone.utc)
        _job_status["ingestion"]["last_result"] = result
        _job_status["ingestion"]["last_error"] = None
    except Exception as exc:
        logger.error("Ingestion job failed: %s", exc)
        _job_status["ingestion"]["last_error"] = str(exc)
        _job_status["ingestion"]["last_run"] = datetime.now(timezone.utc)


def _enrichment_job(app) -> None:
    try:
        from app.services.enrichment import run_enrichment
        result = run_enrichment(app)
        _job_status["enrichment"]["last_run"] = datetime.now(timezone.utc)
        _job_status["enrichment"]["last_result"] = result
        _job_status["enrichment"]["last_error"] = None
    except Exception as exc:
        logger.error("Enrichment job failed: %s", exc)
        _job_status["enrichment"]["last_error"] = str(exc)
        _job_status["enrichment"]["last_run"] = datetime.now(timezone.utc)


def _scoring_job(app) -> None:
    """
    Run Member B's anomaly model over unenriched IOCs, then create alerts.
    If the model is not yet trained/present, this is a no-op.
    """
    try:
        from app.ml.predict import score_pending_iocs
        from app.services.alerting import run_alerting

        with app.app_context():
            score_result = score_pending_iocs(app)
            _job_status["scoring"]["last_result"] = score_result

        alert_result = run_alerting(app)
        _job_status["scoring"]["last_run"] = datetime.now(timezone.utc)
        _job_status["scoring"]["last_error"] = None
        _job_status["scoring"]["last_result"] = {
            "scoring": score_result,
            "alerting": alert_result,
        }
    except Exception as exc:
        logger.error("Scoring job failed: %s", exc)
        _job_status["scoring"]["last_error"] = str(exc)
        _job_status["scoring"]["last_run"] = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Scheduler lifecycle
# ---------------------------------------------------------------------------

def start_scheduler(app) -> BackgroundScheduler:
    """
    Create and start the APScheduler BackgroundScheduler.
    Safe to call only once — re-entrant calls are ignored.
    """
    global _scheduler

    if _scheduler is not None and _scheduler.running:
        logger.warning("Scheduler is already running, skipping start")
        return _scheduler

    interval_minutes: int = app.config.get("INGESTION_INTERVAL_MINUTES", 60)

    _scheduler = BackgroundScheduler(daemon=True)

    _scheduler.add_job(
        func=_ingestion_job,
        args=[app],
        trigger=IntervalTrigger(minutes=interval_minutes),
        id="ingestion",
        name="IOC Ingestion",
        replace_existing=True,
        misfire_grace_time=300,
    )

    _scheduler.add_job(
        func=_enrichment_job,
        args=[app],
        trigger=IntervalTrigger(minutes=interval_minutes + 5),
        id="enrichment",
        name="IOC Enrichment",
        replace_existing=True,
        misfire_grace_time=300,
    )

    _scheduler.add_job(
        func=_scoring_job,
        args=[app],
        trigger=IntervalTrigger(minutes=interval_minutes + 10),
        id="scoring",
        name="Anomaly Scoring + Alerting",
        replace_existing=True,
        misfire_grace_time=300,
    )

    _scheduler.start()
    logger.info(
        "Scheduler started — ingestion every %d min, enrichment every %d min, "
        "scoring every %d min",
        interval_minutes,
        interval_minutes + 5,
        interval_minutes + 10,
    )
    return _scheduler


def stop_scheduler() -> None:
    """Gracefully shut down the scheduler."""
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("Scheduler stopped")
