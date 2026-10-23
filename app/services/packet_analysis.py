"""Metadata-only packet analysis and threat decision logic."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

SUSPICIOUS_PORTS = {21, 22, 23, 25, 110, 135, 139, 1433, 3306, 3389, 4444, 5900, 6379}
VALID_PROTOCOLS = {"tcp", "udp", "icmp", "other"}


class PacketValidationError(ValueError):
    """Raised when packet metadata is incomplete or unsafe to process."""


@dataclass(frozen=True)
class PacketAnalysis:
    source_ip: str
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str
    score: float
    severity: str
    threat_type: str
    indicators: tuple[str, ...]
    features: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "score": self.score,
            "severity": self.severity,
            "threat_type": self.threat_type,
            "indicators": list(self.indicators),
            "features": self.features,
        }


def _port(value: Any, name: str) -> int | None:
    if value is None:
        return None
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise PacketValidationError(f"{name} must be an integer") from exc
    if not 0 <= result <= 65535:
        raise PacketValidationError(f"{name} must be between 0 and 65535")
    return result


def analyze_packet(packet: dict[str, Any]) -> PacketAnalysis:
    """Score packet metadata without accepting or inspecting payload bytes."""
    if not isinstance(packet, dict):
        raise PacketValidationError("packet must be a JSON object")
    try:
        source_ip = str(packet.get("src_ip") or "")
        ipaddress.ip_address(source_ip)
    except ValueError as exc:
        raise PacketValidationError("src_ip must be a valid IP address") from exc

    destination_ip = packet.get("dst_ip")
    if destination_ip:
        try:
            ipaddress.ip_address(str(destination_ip))
        except ValueError as exc:
            raise PacketValidationError("dst_ip must be a valid IP address") from exc
        destination_ip = str(destination_ip)
    else:
        destination_ip = None

    protocol = str(packet.get("protocol") or "tcp").lower()
    if protocol not in VALID_PROTOCOLS:
        raise PacketValidationError(f"protocol must be one of {sorted(VALID_PROTOCOLS)}")
    source_port = _port(packet.get("src_port"), "src_port")
    destination_port = _port(packet.get("dst_port"), "dst_port")

    packets = int(packet.get("packets", 1))
    bytes_out = int(packet.get("bytes_out", 0))
    duration_ms = int(packet.get("duration_ms", 0))
    if packets < 1 or bytes_out < 0 or duration_ms < 0:
        raise PacketValidationError("packets must be positive and byte/duration values cannot be negative")

    indicators: list[str] = []
    score = 0.0
    if destination_port in SUSPICIOUS_PORTS:
        score += 0.35
        indicators.append(f"suspicious_destination_port:{destination_port}")
    if protocol == "tcp" and str(packet.get("tcp_flags") or "").upper() in {"SYN", "SYN,FIN", "SYN,RST"}:
        score += 0.20
        indicators.append("suspicious_tcp_flags")
    if packets >= 100 and duration_ms <= 1000:
        score += 0.30
        indicators.append("high_rate_flow")
    if packets >= 20 and bytes_out / packets < 20:
        score += 0.15
        indicators.append("low_payload_scan_pattern")
    score = round(min(score, 1.0), 4)
    if score >= 0.9:
        severity, threat_type = "critical", "network_attack"
    elif score >= 0.8:
        severity, threat_type = "high", "network_attack"
    elif score >= 0.6:
        severity, threat_type = "medium", "suspicious_flow"
    elif score >= 0.35:
        severity, threat_type = "low", "suspicious_connection"
    else:
        severity, threat_type = "info", "benign"

    features = {
        "packets": packets,
        "bytes_out": bytes_out,
        "duration_ms": duration_ms,
        "tcp_flags": str(packet.get("tcp_flags") or "").upper(),
    }
    return PacketAnalysis(
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        score=score,
        severity=severity,
        threat_type=threat_type,
        indicators=tuple(indicators),
        features=features,
    )
