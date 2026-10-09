"""Optional MISP and OpenCTI connectors.

The connectors are intentionally isolated from ingestion. An unavailable
sharing platform is recorded and reported without stopping public-feed jobs.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from app import db
from app.models.audit_log import AuditAction, AuditLog
from app.models.intel_context import IntelContext
from app.models.ioc import IOC, IOCType
from app.services.ingestion import ingest_iocs

logger = logging.getLogger(__name__)


def _misp_client(config: dict[str, Any]):
    from pymisp import PyMISP
    return PyMISP(config["MISP_URL"], config["MISP_KEY"], ssl=config.get("MISP_VERIFY_SSL", True))


def pull_misp(config: dict[str, Any], limit: int = 100) -> dict[str, int]:
    if not config.get("MISP_URL") or not config.get("MISP_KEY"):
        return {"fetched": 0, "inserted": 0, "duplicates": 0, "skipped": 0}
    client = _misp_client(config)
    events = client.search(controller="events", limit=limit, metadata=True)
    entries: list[dict[str, Any]] = []
    contexts: list[dict[str, Any]] = []
    for event in events or []:
        event_id = str(event.get("Event", event).get("id", ""))
        for attribute in event.get("Event", event).get("Attribute", []):
            value = attribute.get("value", "").strip()
            kind = _misp_type(attribute.get("type", ""), value)
            if not value or not kind:
                continue
            entries.append({"value": value, "type": kind, "source": "misp"})
            contexts.append({"value": value, "external_id": event_id, "data": event})
    inserted, duplicates = ingest_iocs(entries)
    _store_contexts("misp", contexts)
    return {"fetched": len(entries), "inserted": inserted, "duplicates": duplicates,
            "skipped": len(entries) - inserted - duplicates}


def publish_misp(ioc: IOC, config: dict[str, Any]) -> str:
    if not config.get("MISP_URL") or not config.get("MISP_KEY"):
        raise RuntimeError("MISP_URL and MISP_KEY are required")
    client = _misp_client(config)
    from pymisp import MISPEvent, MISPAttribute
    event = MISPEvent()
    event.info = f"WolfEye high-confidence finding: {ioc.value}"
    event.distribution = 0
    event.add_attribute(MISPAttribute(type=ioc.type, value=ioc.value, to_ids=True))
    created = client.add_event(event)
    event_id = str(getattr(created, "id", created.get("Event", {}).get("id", "")))
    db.session.add(AuditLog(ioc_id=ioc.id, action=AuditAction.STATUS_CHANGED,
                            performed_by="system", detail=f"published_to_misp:{event_id}"))
    db.session.commit()
    return event_id


def pull_opencti(config: dict[str, Any], limit: int = 100) -> dict[str, int]:
    if not config.get("OPENCTI_URL") or not config.get("OPENCTI_TOKEN"):
        return {"fetched": 0, "inserted": 0, "duplicates": 0, "skipped": 0}
    from pycti import OpenCTIApiClient
    client = OpenCTIApiClient(config["OPENCTI_URL"], config["OPENCTI_TOKEN"])
    indicators = client.indicator.list(first=limit) or []
    entries: list[dict[str, Any]] = []
    contexts: list[dict[str, Any]] = []
    for indicator in indicators:
        value = _stix_value(indicator.get("pattern", ""))
        kind = _misp_type(indicator.get("pattern_type", ""), value)
        if value and kind:
            entries.append({"value": value, "type": kind, "source": "opencti"})
            contexts.append({"value": value, "external_id": indicator.get("id"), "data": indicator})
    inserted, duplicates = ingest_iocs(entries)
    _store_contexts("opencti", contexts)
    return {"fetched": len(entries), "inserted": inserted, "duplicates": duplicates,
            "skipped": len(entries) - inserted - duplicates}


def _store_contexts(provider: str, contexts: list[dict[str, Any]]) -> None:
    for item in contexts:
        ioc = IOC.query.filter_by(value=item["value"]).first()
        if not ioc:
            continue
        exists = IntelContext.query.filter_by(
            ioc_id=ioc.id, provider=provider, external_id=item.get("external_id")
        ).first()
        if exists:
            continue
        db.session.add(IntelContext(
            ioc_id=ioc.id, provider=provider, external_id=item.get("external_id"),
            context_json=json.dumps(item.get("data", {}), default=str),
        ))
    db.session.commit()


def _misp_type(raw_type: str, value: str) -> str | None:
    raw = raw_type.lower()
    if "ip" in raw:
        return IOCType.IP
    if "domain" in raw:
        return IOCType.DOMAIN
    if "url" in raw:
        return IOCType.URL
    if "hash" in raw or raw in {"md5", "sha1", "sha256"}:
        return IOCType.HASH
    if "email" in raw:
        return IOCType.EMAIL
    return None


def _stix_value(pattern: str) -> str:
    marker = " = '"
    if marker in pattern:
        return pattern.split(marker, 1)[1].split("'", 1)[0]
    return ""
