"""Inline adapters for Flask middleware and reverse-proxy deployments."""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime
from typing import Any

from werkzeug.wrappers import Request, Response

from core.inline import InlinePolicy, InlineRequest, InlineResult
from core.lists import EnforcementLists, ListEntry
from core.rate import RateEngine

logger = logging.getLogger(__name__)


def build_policy(config: Any, *, lists: EnforcementLists | None = None) -> InlinePolicy:
    """Build a policy from application configuration.

    The caller may replace the list snapshot periodically from
    ``/api/enforcement/lists`` when running a separate data-plane process.
    """
    enforcement_lists = lists or EnforcementLists()
    rate_engine = RateEngine(
        requests_limit=config.get("RATE_LIMIT_REQUESTS", 100),
        connections_limit=config.get("RATE_LIMIT_CONNECTIONS", 50),
        window_seconds=config.get("RATE_WINDOW_SECONDS", 10),
        escalation_minutes=tuple(config.get("BLOCK_ESCALATION", [10, 60, 1440])),
        own_networks=tuple(config.get("OWN_NETWORKS", ())),
    )
    model_scorer = None
    if config.get("FLOW_MODEL_MODE", "shadow") in {"shadow", "advisory"}:
        from app.services.flow_model import LiveFlowModel

        model_scorer = LiveFlowModel(config.get("FLOW_MODEL_MODE", "shadow"))
    return InlinePolicy(
        lists=enforcement_lists,
        rate_engine=rate_engine,
        model_scorer=model_scorer,
        blocking_enabled=config.get("BLOCKING_ENABLED", True),
        dry_run=config.get("DRY_RUN", False),
    )


class FlaskInlineMiddleware:
    """WSGI middleware for Mode 2 and as the request side of Mode 1.

    Suspicious requests are never rejected here. Only an active blocklist match
    or the rule-based rate engine can produce a rejecting response.
    """

    def __init__(
        self,
        application: Callable,
        policy: InlinePolicy,
        *,
        mode: str = "middleware",
        node_id: str = "default-node",
        on_review: Callable[[InlineRequest, InlineResult], None] | None = None,
    ) -> None:
        if mode not in {"gateway", "middleware", "host"}:
            raise ValueError("mode must be gateway, middleware or host")
        self.application = application
        self.policy = policy
        self.mode = mode
        self.node_id = node_id
        self.on_review = on_review

    def __call__(self, environ: dict[str, Any], start_response: Callable) -> Any:
        request = Request(environ)
        source_ip = request.remote_addr or "0.0.0.0"
        observation = InlineRequest(
            source_ip=source_ip,
            host=request.host,
            url=request.url,
            new_connection=request.headers.get("Connection", "").lower() == "upgrade",
            metadata={
                "method": request.method,
                "path": request.path,
                "user_agent": request.user_agent.string if request.user_agent else None,
                "flow_features": environ.get("wolfeye.flow_features"),
            },
        )
        result = self.policy.evaluate(observation)
        if result.decision.value in {"blocked", "dry_run_blocked"}:
            status = "429 Too Many Requests" if result.rate.exceeded else "403 Forbidden"
            response = Response(
                "Request blocked by WolfEye\n",
                status=status,
                content_type="text/plain",
                headers={"X-WolfEye-Decision": result.decision.value},
            )
            return response(environ, start_response)
        if result.decision.value == "review" and self.on_review is not None:
            self.on_review(observation, result)
        environ["wolfeye.result"] = result
        environ["wolfeye.node_id"] = self.node_id
        return self.application(environ, start_response)


def refresh_lists(target: EnforcementLists, payload: dict[str, Any]) -> None:
    """Atomically load the JSON shape returned by the enforcement API."""
    def entries(values: Any) -> list[ListEntry]:
        if not isinstance(values, list):
            raise ValueError("enforcement list must be an array")
        return [
            ListEntry(
                kind=str(item["kind"]),
                value=str(item["value"]),
                expires_at=(
                    datetime.fromisoformat(str(item["expires_at"]).replace("Z", "+00:00"))
                    if item.get("expires_at")
                    else None
                ),
            )
            for item in values
            if isinstance(item, dict) and item.get("kind") and item.get("value")
        ]

    version = int(payload.get("version", 0))
    target.replace(
        allowlist=entries(payload.get("allowlist", [])),
        blocklist=entries(payload.get("blocklist", [])),
        version=version,
    )
