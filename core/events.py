"""Validated, privacy-preserving event records emitted by data-plane nodes."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from core.redaction import redact_query, redact_headers


class EventValidationError(ValueError):
    """Raised when an event does not satisfy the node event contract."""


_MODES = {"gateway", "middleware", "host"}
_DIRECTIONS = {"inbound", "outbound"}
_DECISIONS = {"allowed", "auto_blocked", "dry_run_blocked"}
_PROTOCOLS = {"tcp", "udp", "icmp", "other"}


@dataclass(slots=True)
class Event:
    """Request or flow metadata safe to send to the control plane.

    Bodies and sensitive headers are intentionally not represented by this
    type. ``flow_features`` is ordered by the model artifact, not by this
    schema.
    """

    node_id: str
    mode: str
    direction: str
    src_ip: str
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "tcp"
    method: str | None = None
    host: str | None = None
    path: str | None = None
    query_redacted: str | None = None
    user_agent: str | None = None
    status_code: int | None = None
    bytes_in: int = 0
    bytes_out: int = 0
    flow_id: str | None = None
    flow_features: list[float] | None = None
    decision: str = "allowed"
    decision_reason: str | None = None
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ts_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def validate(self) -> None:
        """Validate values before serialization."""
        if not self.event_id or not self.node_id or not self.src_ip:
            raise EventValidationError("event_id, node_id and src_ip are required")
        if self.mode not in _MODES:
            raise EventValidationError("mode must be gateway, middleware or host")
        if self.direction not in _DIRECTIONS:
            raise EventValidationError("direction must be inbound or outbound")
        if self.decision not in _DECISIONS:
            raise EventValidationError("unsupported decision")
        if self.protocol.lower() not in _PROTOCOLS:
            raise EventValidationError("unsupported protocol")
        for name, value in (("src_port", self.src_port), ("dst_port", self.dst_port)):
            if value is not None and not 0 <= value <= 65535:
                raise EventValidationError(f"{name} must be between 0 and 65535")
        for name, value in (("bytes_in", self.bytes_in), ("bytes_out", self.bytes_out)):
            if value < 0:
                raise EventValidationError(f"{name} cannot be negative")
        if self.status_code is not None and not 100 <= self.status_code <= 599:
            raise EventValidationError("status_code must be between 100 and 599")
        if self.flow_features is not None and len(self.flow_features) != 52:
            raise EventValidationError("flow_features must contain exactly 52 values")

    def to_dict(self) -> dict[str, Any]:
        """Return a validated JSON-compatible event dictionary."""
        self.validate()
        return asdict(self)

    def to_json(self) -> str:
        """Serialize the event without ever including request/response bodies."""
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_request_metadata(
        cls,
        metadata: Mapping[str, Any],
        *,
        node_id: str,
        mode: str,
        direction: str = "inbound",
    ) -> "Event":
        """Build an event from adapter metadata with query/header redaction."""
        headers = metadata.get("headers") or {}
        query = metadata.get("query")
        event = cls(
            node_id=node_id,
            mode=mode,
            direction=direction,
            src_ip=str(metadata.get("src_ip") or ""),
            dst_ip=metadata.get("dst_ip"),
            src_port=metadata.get("src_port"),
            dst_port=metadata.get("dst_port"),
            protocol=str(metadata.get("protocol") or "tcp").lower(),
            method=metadata.get("method"),
            host=metadata.get("host"),
            path=metadata.get("path"),
            query_redacted=redact_query(str(query)) if query is not None else None,
            user_agent=redact_headers(headers).get("User-Agent"),
            status_code=metadata.get("status_code"),
            bytes_in=metadata.get("bytes_in", 0),
            bytes_out=metadata.get("bytes_out", 0),
            flow_id=metadata.get("flow_id"),
            flow_features=metadata.get("flow_features"),
            decision=metadata.get("decision", "allowed"),
            decision_reason=metadata.get("decision_reason"),
        )
        event.validate()
        return event
