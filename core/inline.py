"""Synchronous inline request decisions shared by all deployment adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable

from core.lists import EnforcementLists
from core.rate import RateDecision, RateEngine


class InlineDecision(StrEnum):
    """Decisions an adapter may enforce for a request."""

    ALLOWED = "allowed"
    REVIEW = "review"
    BLOCKED = "blocked"
    DRY_RUN_BLOCKED = "dry_run_blocked"


@dataclass(frozen=True, slots=True)
class InlineRequest:
    """Metadata visible to an inline adapter.

    Bodies are deliberately absent. A URL may be supplied by a TLS-terminating
    adapter; encrypted pass-through adapters should provide only host/SNI data.
    """

    source_ip: str
    destination_ip: str | None = None
    host: str | None = None
    url: str | None = None
    new_connection: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class InlineResult:
    decision: InlineDecision
    reason: str
    rate: RateDecision
    signals: tuple[str, ...] = ()
    model: dict[str, Any] | None = None

    @property
    def allowed(self) -> bool:
        return self.decision in {InlineDecision.ALLOWED, InlineDecision.REVIEW}

    @property
    def automatically_blocked(self) -> bool:
        return self.decision in {
            InlineDecision.BLOCKED,
            InlineDecision.DRY_RUN_BLOCKED,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "rate": {
                "exceeded": self.rate.exceeded,
                "offence": self.rate.offence,
                "block_minutes": self.rate.block_minutes,
            },
            "signals": list(self.signals),
            "model": self.model,
        }


class InlinePolicy:
    """Evaluate a request without allowing ML or intel to block it."""

    def __init__(
        self,
        *,
        lists: EnforcementLists,
        rate_engine: RateEngine,
        intel_matcher: Callable[[InlineRequest], tuple[str, ...]] | None = None,
        model_scorer: Callable[[InlineRequest], dict[str, Any] | None] | None = None,
        blocking_enabled: bool = True,
        dry_run: bool = False,
    ) -> None:
        self.lists = lists
        self.rate_engine = rate_engine
        self.intel_matcher = intel_matcher
        self.model_scorer = model_scorer
        self.blocking_enabled = blocking_enabled
        self.dry_run = dry_run

    def evaluate(self, request: InlineRequest) -> InlineResult:
        """Return the only decision an adapter may enforce for this request."""
        allowlisted = self.lists.is_allowed(request.source_ip)
        for value, kind in ((request.host, "domain"), (request.url, "url_prefix")):
            if value and self.lists.is_allowed(value, kind=kind):
                allowlisted = True
        rate = self.rate_engine.check(
            request.source_ip,
            new_connection=request.new_connection,
            allowlisted=allowlisted,
        )

        blocked = self.lists.is_blocked(request.source_ip)
        for value, kind in ((request.host, "domain"), (request.url, "url_prefix")):
            if value and self.lists.is_blocked(value, kind=kind):
                blocked = True
        if blocked and self.blocking_enabled:
            return InlineResult(
                InlineDecision.BLOCKED,
                "source is on the blocklist",
                rate,
            )

        if rate.exceeded:
            if self.blocking_enabled and not self.dry_run:
                decision = InlineDecision.BLOCKED
            else:
                decision = InlineDecision.DRY_RUN_BLOCKED
            return InlineResult(decision, rate.reason or "rate limit exceeded", rate)

        signals = self.intel_matcher(request) if self.intel_matcher else ()
        model = self.model_scorer(request) if self.model_scorer else None
        model_is_advisory = model is not None and model.get("mode") == "advisory"
        if signals or model_is_advisory:
            return InlineResult(
                InlineDecision.REVIEW,
                "suspicious request allowed pending expert review",
                rate,
                tuple(signals),
                model,
            )

        return InlineResult(InlineDecision.ALLOWED, "no blocking signal", rate, model=model)
