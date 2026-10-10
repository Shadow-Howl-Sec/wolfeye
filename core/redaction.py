"""Default-on request metadata redaction rules."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode

_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie"}
_SENSITIVE_QUERY_KEYS = {"token", "key", "password", "secret"}


def redact_headers(headers: object) -> dict[str, str]:
    """Drop credential-bearing headers while retaining safe metadata."""
    if not hasattr(headers, "items"):
        return {}
    return {
        str(key): str(value)
        for key, value in headers.items()  # type: ignore[union-attr]
        if str(key).lower() not in _SENSITIVE_HEADERS
    }


def redact_query(query: str) -> str:
    """Replace values for sensitive query keys and preserve other parameters."""
    pairs = parse_qsl(query.lstrip("?"), keep_blank_values=True)
    return urlencode(
        [
            (key, "[REDACTED]" if key.lower() in _SENSITIVE_QUERY_KEYS else value)
            for key, value in pairs
        ],
        doseq=True,
    )
