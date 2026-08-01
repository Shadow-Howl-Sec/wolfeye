"""
app/services/ingestion.py
--------------------------
Pulls Indicators of Compromise from public threat feeds and persists
deduplicated, normalised records into the IOC table.

Supported feeds:
    * URLhaus  (abuse.ch) — no API key required
    * ThreatFox (abuse.ch) — API key optional (higher rate limit with key)

The service is called directly by the APScheduler job in scheduler.py.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import requests
from sqlalchemy.exc import IntegrityError

from app import db
from app.models.ioc import IOC, IOCType
from app.models.audit_log import AuditLog, AuditAction

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

REQUEST_TIMEOUT = 15  # seconds


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _normalize_ioc(
    value: str,
    ioc_type: str,
    source: str,
    first_seen: datetime | None = None,
) -> dict[str, Any]:
    """Return a dict matching the IOC model's required fields."""
    return {
        "value": value.strip()[:2048],
        "type": ioc_type,
        "source": source,
        "first_seen": first_seen or datetime.now(timezone.utc),
    }


# ---------------------------------------------------------------------------
# URLhaus feed
# ---------------------------------------------------------------------------

def fetch_urlhaus(limit: int = 100) -> list[dict[str, Any]]:
    """
    Fetch recent malicious URLs from URLhaus.

    Returns:
        List of normalised IOC dicts.
    """
    logger.info("Fetching URLhaus recent URLs (limit=%d)", limit)
    try:
        resp = requests.post(
            URLHAUS_RECENT_URL,
            data={"limit": limit},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        logger.error("URLhaus fetch failed: %s", exc)
        return []

    iocs: list[dict] = []
    for entry in data.get("urls", []):
        url = entry.get("url")
        if not url:
            continue
        first_seen_raw = entry.get("date_added")
        try:
            first_seen = datetime.fromisoformat(first_seen_raw.replace(" ", "T"))
        except (TypeError, ValueError):
            first_seen = None

        iocs.append(_normalize_ioc(url, IOCType.URL, "urlhaus", first_seen))

    logger.info("URLhaus: fetched %d URLs", len(iocs))
    return iocs


# ---------------------------------------------------------------------------
# ThreatFox feed
# ---------------------------------------------------------------------------

def fetch_threatfox(days: int = 1, api_key: str = "") -> list[dict[str, Any]]:
    """
    Fetch recent IOCs from ThreatFox.

    Args:
        days: Look-back window in days (1–7).
        api_key: Optional API key for higher rate limits.

    Returns:
        List of normalised IOC dicts.
    """
    logger.info("Fetching ThreatFox IOCs (days=%d)", days)
    payload: dict[str, Any] = {"query": "get_iocs", "days": days}
    headers = {"Auth-Key": api_key} if api_key else {}

    try:
        resp = requests.post(
            THREATFOX_API_URL,
            json=payload,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        logger.error("ThreatFox fetch failed: %s", exc)
        return []

    if data.get("query_status") != "ok":
        logger.warning("ThreatFox returned status: %s", data.get("query_status"))
        return []

    type_map = {
        "ip:port": IOCType.IP,
        "domain": IOCType.DOMAIN,
        "url": IOCType.URL,
        "md5_hash": IOCType.HASH,
        "sha256_hash": IOCType.HASH,
    }

    iocs: list[dict] = []
    for entry in data.get("data", []):
        raw_type = entry.get("ioc_type", "")
        ioc_type = type_map.get(raw_type, IOCType.URL)
        value = entry.get("ioc", "")
        if not value:
            continue

        # Strip port suffix for IP:port indicators
        if raw_type == "ip:port" and ":" in value:
            value = value.split(":")[0]

        first_seen_raw = entry.get("first_seen")
        try:
            first_seen = datetime.fromisoformat(first_seen_raw.replace(" ", "T"))
        except (TypeError, ValueError):
            first_seen = None

        iocs.append(_normalize_ioc(value, ioc_type, "threatfox", first_seen))

    logger.info("ThreatFox: fetched %d IOCs", len(iocs))
    return iocs


# ---------------------------------------------------------------------------
# Persist & deduplicate
# ---------------------------------------------------------------------------

def ingest_iocs(ioc_dicts: list[dict[str, Any]], app_context=None) -> tuple[int, int]:
    """
    Persist a list of normalised IOC dicts into the database.

    Uses INSERT-then-catch-IntegrityError for deduplication (unique constraint
    on value+type). This is more efficient than SELECT-first for large batches.

    Returns:
        (inserted_count, duplicate_count)
    """
    inserted = 0
    duplicates = 0

    for entry in ioc_dicts:
        try:
            ioc = IOC(
                value=entry["value"],
                type=entry["type"],
                source=entry["source"],
                first_seen=entry["first_seen"],
            )
            db.session.add(ioc)
            db.session.flush()  # get the id without full commit

            log = AuditLog(
                ioc_id=ioc.id,
                action=AuditAction.INGESTED,
                performed_by="system",
                detail=f"Source: {entry['source']}",
            )
            db.session.add(log)
            inserted += 1
        except IntegrityError:
            db.session.rollback()
            duplicates += 1
        except Exception as exc:
            db.session.rollback()
            logger.error("Unexpected error persisting IOC %r: %s", entry.get("value"), exc)

    db.session.commit()
    logger.info("Ingestion complete — inserted=%d duplicates=%d", inserted, duplicates)
    return inserted, duplicates


# ---------------------------------------------------------------------------
# Orchestration (called by the scheduler)
# ---------------------------------------------------------------------------

def run_ingestion(app) -> dict[str, Any]:
    """
    Full ingestion run: fetch from all feeds then persist.

    Args:
        app: The Flask application instance (used for app context).

    Returns:
        Summary dict with counts per source.
    """
    with app.app_context():
        tf_key = app.config.get("THREATFOX_API_KEY", "")

        urlhaus_iocs = fetch_urlhaus(limit=200)
        threatfox_iocs = fetch_threatfox(days=1, api_key=tf_key)

        all_iocs = urlhaus_iocs + threatfox_iocs
        inserted, dupes = ingest_iocs(all_iocs)

        summary = {
            "urlhaus_fetched": len(urlhaus_iocs),
            "threatfox_fetched": len(threatfox_iocs),
            "total_fetched": len(all_iocs),
            "inserted": inserted,
            "duplicates": dupes,
        }
        logger.info("Ingestion summary: %s", summary)
        return summary
