"""Local sliding-window request and connection rate engine."""

from __future__ import annotations

import ipaddress
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import RLock


@dataclass(frozen=True, slots=True)
class RateDecision:
    allowed: bool
    exceeded: bool = False
    reason: str | None = None
    offence: int = 0
    block_minutes: int = 0


class RateEngine:
    """Per-node rate limiter with safe-network exclusions and escalation."""

    def __init__(
        self,
        *,
        requests_limit: int = 100,
        connections_limit: int = 50,
        window_seconds: int = 10,
        escalation_minutes: tuple[int, ...] = (10, 60, 1440),
        quiet_period_seconds: int = 7 * 24 * 60 * 60,
        own_networks: tuple[str, ...] = (),
        health_sources: tuple[str, ...] = (),
        control_plane_addresses: tuple[str, ...] = (),
        clock: callable = time.monotonic,
    ) -> None:
        if requests_limit < 1 or connections_limit < 1 or window_seconds < 1:
            raise ValueError("rate limits and window must be positive")
        self.requests_limit = requests_limit
        self.connections_limit = connections_limit
        self.window_seconds = window_seconds
        self.escalation_minutes = escalation_minutes or (10,)
        self.quiet_period_seconds = quiet_period_seconds
        self._safe_networks = tuple(ipaddress.ip_network(value, strict=False) for value in own_networks)
        self._health_sources = set(health_sources)
        self._control_plane_addresses = set(control_plane_addresses)
        self._clock = clock
        self._requests: defaultdict[str, deque[float]] = defaultdict(deque)
        self._connections: defaultdict[str, deque[float]] = defaultdict(deque)
        self._offences: dict[str, tuple[int, float]] = {}
        self._lock = RLock()

    def check(self, source_ip: str, *, new_connection: bool = False, allowlisted: bool = False) -> RateDecision:
        if allowlisted or self._is_safe_source(source_ip):
            return RateDecision(allowed=True, reason="safety exclusion")
        now = self._clock()
        with self._lock:
            requests = self._record(self._requests[source_ip], now)
            connections = self._record(self._connections[source_ip], now) if new_connection else len(self._connections[source_ip])
            exceeded = requests > self.requests_limit or connections > self.connections_limit
            if not exceeded:
                return RateDecision(allowed=True)
            offence = self._next_offence(source_ip, now)
            block_minutes = self.escalation_minutes[min(offence - 1, len(self.escalation_minutes) - 1)]
            return RateDecision(
                allowed=False,
                exceeded=True,
                reason=f"rate limit exceeded: requests={requests}, connections={connections}",
                offence=offence,
                block_minutes=block_minutes,
            )

    def _record(self, bucket: deque[float], now: float) -> int:
        cutoff = now - self.window_seconds
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        bucket.append(now)
        return len(bucket)

    def _next_offence(self, source_ip: str, now: float) -> int:
        previous, recorded_at = self._offences.get(source_ip, (0, now))
        offence = previous + 1 if now - recorded_at <= self.quiet_period_seconds else 1
        self._offences[source_ip] = (offence, now)
        return offence

    def _is_safe_source(self, source_ip: str) -> bool:
        if source_ip in self._health_sources or source_ip in self._control_plane_addresses:
            return True
        try:
            address = ipaddress.ip_address(source_ip)
        except ValueError:
            return False
        return address.is_loopback or any(address in network for network in self._safe_networks)
