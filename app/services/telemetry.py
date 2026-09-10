"""Extract indicators from local security-agent observations.

Only metadata is accepted and persisted. The service deliberately does not
read files, execute commands, or retain email/file contents.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any
from app.models.ioc import IOCType

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_HASH_RE = re.compile(r"\b[a-f0-9]{32}(?:[a-f0-9]{8}|[a-f0-9]{32})?\b", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE)


def _ioc(value: str, ioc_type: str, source: str) -> dict[str, str]:
    return {"value": value.strip().rstrip(".,);]"), "type": ioc_type, "source": source}


def _classify(value: str, source: str) -> dict[str, str] | None:
    candidate = value.strip().rstrip(".,);]")
    if not candidate:
        return None
    try:
        ipaddress.ip_address(candidate)
        return _ioc(candidate, IOCType.IP, source)
    except ValueError:
        pass
    if _EMAIL_RE.fullmatch(candidate):
        return _ioc(candidate.lower(), IOCType.EMAIL, source)
    if _HASH_RE.fullmatch(candidate):
        return _ioc(candidate.lower(), IOCType.HASH, source)
    if _URL_RE.fullmatch(candidate):
        return _ioc(candidate, IOCType.URL, source)
    if _DOMAIN_RE.fullmatch(candidate):
        return _ioc(candidate.lower(), IOCType.DOMAIN, source)
    return None


def extract_observation_iocs(observation: dict[str, Any], source: str) -> list[dict[str, str]]:
    """Extract deduplicated indicators from an agent event's metadata."""
    text_values: list[str] = []

    def collect(value: Any) -> None:
        if isinstance(value, str):
            text_values.append(value[:4096])
        elif isinstance(value, dict):
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value[:100]:
                collect(child)

    collect(observation)
    candidates: set[tuple[str, str]] = set()
    for text in text_values:
        matches = set(_URL_RE.findall(text)) | set(_EMAIL_RE.findall(text))
        matches |= set(_HASH_RE.findall(text)) | set(_DOMAIN_RE.findall(text))
        for match in matches:
            item = _classify(match, source)
            if item:
                candidates.add((item["type"], item["value"]))
        for token in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text):
            item = _classify(token, source)
            if item:
                candidates.add((item["type"], item["value"]))
    return [{"type": kind, "value": value, "source": source} for kind, value in sorted(candidates)]


def hash_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    """Hash a local file for an agent; the file itself never leaves the host."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()