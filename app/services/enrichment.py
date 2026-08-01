"""
app/services/enrichment.py
---------------------------
Enriches IOCs by querying external reputation APIs:

    * VirusTotal v3 — malicious detection counts, reputation score
    * AbuseIPDB v2  — abuse confidence score, country, ISP
    * Shodan        — open ports, org, country

Design decisions:
    * Caching: an IOC is not re-queried if its Enrichment row was updated
      within the last CACHE_HOURS hours, respecting free-tier rate limits.
    * Graceful fallback: if an API is down or rate-limited, that source is
      skipped and the others still run (feed-only mode).
    * Raw JSON is stored alongside parsed fields for later reprocessing.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from app import db
from app.models.ioc import IOC, IOCType
from app.models.enrichment import Enrichment
from app.models.audit_log import AuditLog, AuditAction

logger = logging.getLogger(__name__)

CACHE_HOURS = 24       # skip re-enrichment within this window
REQUEST_TIMEOUT = 10   # seconds per API call


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

def _enrich_virustotal(value: str, ioc_type: str, api_key: str) -> dict[str, Any] | None:
    """Query VirusTotal v3 for a URL, domain, IP, or file hash."""
    if not api_key:
        return None

    headers = {"x-apikey": api_key}

    try:
        if ioc_type == IOCType.URL:
            import base64
            url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        elif ioc_type == IOCType.IP:
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
        elif ioc_type == IOCType.DOMAIN:
            endpoint = f"https://www.virustotal.com/api/v3/domains/{value}"
        elif ioc_type == IOCType.HASH:
            endpoint = f"https://www.virustotal.com/api/v3/files/{value}"
        else:
            return None

        resp = requests.get(endpoint, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        stats = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        reputation = (
            data.get("data", {})
            .get("attributes", {})
            .get("reputation", None)
        )

        return {
            "vt_reputation": reputation,
            "vt_detections": stats.get("malicious", 0),
            "vt_total_engines": sum(stats.values()) if stats else None,
            "raw_vt_json": json.dumps(data),
        }
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 429:
            logger.warning("VirusTotal rate limit hit for %r", value)
        else:
            logger.warning("VirusTotal error for %r: %s", value, exc)
        return None
    except requests.RequestException as exc:
        logger.warning("VirusTotal request failed for %r: %s", value, exc)
        return None


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------

def _enrich_abuseipdb(value: str, ioc_type: str, api_key: str) -> dict[str, Any] | None:
    """Query AbuseIPDB v2. Only works for IP indicators."""
    if not api_key or ioc_type != IOCType.IP:
        return None

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": value, "maxAgeInDays": 90, "verbose": True},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        attrs = data.get("data", {})

        return {
            "abuseipdb_score": attrs.get("abuseConfidenceScore"),
            "abuseipdb_country": attrs.get("countryCode"),
            "abuseipdb_isp": attrs.get("isp"),
            "raw_abuseipdb_json": json.dumps(data),
        }
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 429:
            logger.warning("AbuseIPDB rate limit hit for %r", value)
        else:
            logger.warning("AbuseIPDB error for %r: %s", value, exc)
        return None
    except requests.RequestException as exc:
        logger.warning("AbuseIPDB request failed for %r: %s", value, exc)
        return None


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------

def _enrich_shodan(value: str, ioc_type: str, api_key: str) -> dict[str, Any] | None:
    """Query Shodan host info. Only works for IP indicators."""
    if not api_key or ioc_type != IOCType.IP:
        return None

    try:
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{value}",
            params={"key": api_key},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        ports = data.get("ports", [])
        org = data.get("org") or data.get("isp")
        country = data.get("country_code")

        return {
            "shodan_ports": json.dumps(ports),
            "shodan_org": org,
            "shodan_country": country,
            "raw_shodan_json": json.dumps(data),
        }
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code in (404, 429):
            level = logging.WARNING
            msg = "Shodan: no data (404) or rate limit for %r"
            logger.log(level, msg, value)
        else:
            logger.warning("Shodan error for %r: %s", value, exc)
        return None
    except requests.RequestException as exc:
        logger.warning("Shodan request failed for %r: %s", value, exc)
        return None


# ---------------------------------------------------------------------------
# Main enrichment entry point
# ---------------------------------------------------------------------------

def enrich_ioc(ioc: IOC, config: dict[str, str]) -> bool:
    """
    Enrich a single IOC using all configured APIs.

    Args:
        ioc:    The IOC ORM object (must be in session).
        config: App config dict with API keys.

    Returns:
        True if any enrichment data was saved, False otherwise.
    """
    # Cache check: skip if recently enriched
    if ioc.enrichment and ioc.enrichment.last_updated:
        age = datetime.now(timezone.utc) - ioc.enrichment.last_updated.replace(tzinfo=timezone.utc)
        if age < timedelta(hours=CACHE_HOURS):
            logger.debug("Skipping enrichment for IOC %d (cached)", ioc.id)
            return False

    vt_key = config.get("VIRUSTOTAL_API_KEY", "")
    abuse_key = config.get("ABUSEIPDB_API_KEY", "")
    shodan_key = config.get("SHODAN_API_KEY", "")

    vt_data = _enrich_virustotal(ioc.value, ioc.type, vt_key)
    abuse_data = _enrich_abuseipdb(ioc.value, ioc.type, abuse_key)
    shodan_data = _enrich_shodan(ioc.value, ioc.type, shodan_key)

    if not any([vt_data, abuse_data, shodan_data]):
        logger.debug("No enrichment data for IOC %d %r", ioc.id, ioc.value)
        return False

    # Merge results
    enrichment = ioc.enrichment or Enrichment(ioc_id=ioc.id)

    for source_data in (vt_data, abuse_data, shodan_data):
        if source_data:
            for key, val in source_data.items():
                if hasattr(enrichment, key):
                    setattr(enrichment, key, val)

    # Best-effort country resolution
    enrichment.country = (
        (abuse_data or {}).get("abuseipdb_country")
        or (shodan_data or {}).get("shodan_country")
    )
    enrichment.last_updated = datetime.now(timezone.utc)

    db.session.add(enrichment)

    log = AuditLog(
        ioc_id=ioc.id,
        action=AuditAction.ENRICHED,
        performed_by="system",
        detail=f"VT={'ok' if vt_data else 'skip'} "
               f"Abuse={'ok' if abuse_data else 'skip'} "
               f"Shodan={'ok' if shodan_data else 'skip'}",
    )
    db.session.add(log)
    db.session.commit()
    return True


def run_enrichment(app, batch_size: int = 50) -> dict[str, int]:
    """
    Enrich all un-enriched (or stale) IOCs in batches.

    Args:
        app:        Flask application instance.
        batch_size: Max IOCs to process per scheduler run.

    Returns:
        Summary dict.
    """
    with app.app_context():
        config = app.config

        # Pick IOCs with no enrichment or stale enrichment
        stale_cutoff = datetime.now(timezone.utc) - timedelta(hours=CACHE_HOURS)
        iocs = (
            IOC.query
            .outerjoin(Enrichment)
            .filter(
                db.or_(
                    Enrichment.id.is_(None),
                    Enrichment.last_updated < stale_cutoff,
                )
            )
            .limit(batch_size)
            .all()
        )

        enriched = 0
        skipped = 0
        for ioc in iocs:
            result = enrich_ioc(ioc, config)
            if result:
                enriched += 1
            else:
                skipped += 1

        summary = {"iocs_processed": len(iocs), "enriched": enriched, "skipped": skipped}
        logger.info("Enrichment run: %s", summary)
        return summary
