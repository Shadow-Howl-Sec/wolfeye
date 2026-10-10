"""In-memory enforcement lists shared by gateway, middleware and host nodes."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock


@dataclass(frozen=True, slots=True)
class ListEntry:
    kind: str
    value: str
    expires_at: datetime | None = None

    def active(self, now: datetime | None = None) -> bool:
        return self.expires_at is None or self.expires_at > (now or datetime.now(timezone.utc))


class EnforcementLists:
    """Atomic, lock-protected allowlist and blocklist matcher."""

    def __init__(self) -> None:
        self._allow: tuple[ListEntry, ...] = ()
        self._block: tuple[ListEntry, ...] = ()
        self._lock = RLock()
        self.version = 0

    def replace(self, *, allowlist: list[ListEntry], blocklist: list[ListEntry], version: int) -> None:
        if version < self.version:
            return
        with self._lock:
            self._allow = tuple(allowlist)
            self._block = tuple(blocklist)
            self.version = version

    def is_allowed(self, value: str, *, kind: str = "ip") -> bool:
        return self._matches(value, self._allow, kind=kind)

    def is_blocked(self, value: str, *, kind: str = "ip") -> bool:
        return self._matches(value, self._block, kind=kind)

    @staticmethod
    def _matches(value: str, entries: tuple[ListEntry, ...], *, kind: str) -> bool:
        now = datetime.now(timezone.utc)
        for entry in entries:
            if (
                entry.kind not in ({kind, "cidr"} if kind == "ip" else {kind})
                or not entry.active(now)
            ):
                continue
            if kind in {"ip", "cidr"}:
                try:
                    candidate = ipaddress.ip_address(value)
                    network = ipaddress.ip_network(entry.value, strict=False)
                    if candidate in network:
                        return True
                except ValueError:
                    continue
            elif kind == "domain" and value.lower() == entry.value.lower():
                return True
            elif kind == "url_prefix" and value.startswith(entry.value):
                return True
        return False
