import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Channel(str, Enum):
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"


class Category(str, Enum):
    INFRASTRUCTURE = "infrastructure"
    APPLICATION = "application"
    SECURITY = "security"
    NETWORK = "network"
    DATABASE = "database"


@dataclass
class Incident:
    id: str
    title: str
    severity: Severity
    category: Category
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    dedup_key: Optional[str] = None


@dataclass
class RateLimiter:
    max_requests: int
    window_seconds: int
    _timestamps: List[float] = field(default_factory=list)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def allow(self) -> bool:
        async with self._lock:
            now = time.monotonic()
            cutoff = now - self.window_seconds
            self._timestamps = [t for t in self._timestamps if t > cutoff]
            if len(self._timestamps) >= self.max_requests:
                return False
            self._timestamps.append(now)
            return True


@dataclass
class RoutingRule:
    channels: List[Channel]
    severities: List[Severity]
    categories: List[Category]

    def matches(self, incident: Incident) -> bool:
        sev_ok = not self.severities or incident.severity in self.severities
        cat_ok = not self.categories or incident.category in self.categories
        return sev_ok and cat_ok


DEFAULT_ROUTING_RULES: List[RoutingRule] = [
    RoutingRule(
        channels=[Channel.PAGERDUTY, Channel.SLACK, Channel.EMAIL],
        severities=[Severity.CRITICAL],
        categories=[],
    ),
    RoutingRule(
        channels=[Channel.PAGERDUTY, Channel.SLACK],
        severities=[Severity.HIGH],
        categories=[Category.SECURITY, Category.INFRASTRUCTURE],
    ),
    RoutingRule(
        channels=[Channel.SLACK, Channel.EMAIL],
        severities=[Severity.HIGH],
        categories=[],
    ),
    RoutingRule(
        channels=[Channel.SLACK],
        severities=[Severity.MEDIUM],
        categories=[],
    ),
    RoutingRule(
        channels=[Channel.SLACK],
        severities=[Severity.LOW, Severity.INFO],
        categories=[Category.SECURITY],
    ),
]


class NotificationDispatcher:
    def __init__(
        self,
        slack_webhook_url: Optional[str] = None,
        pagerduty_routing_key: Optional[str] = None,
        pagerduty_api_url: str = "https://events.pagerduty.com/v2/enqueue",
        email_endpoint: Optional[str] = None,
        routing_rules: Optional[List[RoutingRule]] = None,
        rate_limits: Optional[Dict[Channel, RateLimiter]] = None,
    ):
        self.slack_webhook_url = slack_webhook_url
        self.pagerduty_routing_key = pagerduty_routing_key
        self.pagerduty_api_url = pagerduty_api_url
        self.email_endpoint = email_endpoint
        self.routing_rules = routing_rules or DEFAULT_ROUTING_RULES
        self._client = httpx.AsyncClient(timeout=15.0)
        self._rate_limiters = rate_limits or {
            Channel.SLACK: RateLimiter(max_requests=60, window_seconds=60),
            Channel.PAGERDUTY: RateLimiter(max_requests=20, window_seconds=60),
            Channel.EMAIL: RateLimiter(max_requests=30, window_seconds=60),
        }
        self._channel_handlers: Dict[Channel, Callable] = {
            Channel.SLACK: self._send_slack,
            Channel.PAGERDUTY: self._send_pagerduty,
            Channel.EMAIL: self._send_email,
        }

    def resolve_channels(self, incident: Incident) -> List[Channel]:
        matched: set = set()
        for rule in self.routing_rules:
            if rule.matches(incident):
                matched.update(rule.channels)
        return sorted(matched, key=lambda c: c.value)

    async def dispatch(self, incident: Incident) -> Dict[str, Any]:
        channels = self.resolve_channels(incident)
        results: Dict[str, Any] = {}
        tasks = []
        for ch in channels:
            limiter = self._rate_limiters.get(ch)
            if limiter and not await limiter.allow():
                results[ch.value] = {"status": "rate_limited"}
                logger.warning("Rate limited channel %s for incident %s", ch.value, incident.id)
                continue
            handler = self._channel_handlers.get(ch)
            if handler:
                tasks.append((ch, handler(incident)))
        for ch, coro in tasks:
            try:
                result = await coro
                results[ch.value] = {"status": "sent", "detail": result}
            except Exception as exc:
                logger.exception("Failed dispatch to %s for incident %s", ch.value, incident.id)
                results[ch.value] = {"status": "error", "error": str(exc)}
        logger.info("Dispatched incident %s to %s", incident.id, list(results.keys()))
        return {"incident_id": incident.id, "dispatch": results}

    async def _send_slack(self, incident: Incident) -> Dict[str, str]:
        if not self.slack_webhook_url:
            raise ValueError("Slack webhook URL not configured")
        severity_emoji = {
            Severity.CRITICAL: "🔴", Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡", Severity.LOW: "🔵", Severity.INFO: "⚪",
        }
        emoji = severity_emoji.get(incident.severity, "⚠️")
        payload = {
            "text": f"{emoji} [{incident.severity.value.upper()}] {incident.title}",
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn",
                 "text": f"{emoji} *[{incident.severity.value.upper()}]* {incident.title}"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Category:* {incident.category.value}"},
                    {"type": "mrkdwn", "text": f"*Incident ID:* {incident.id}"},
                ]},
                {"type": "section", "text": {"type": "mrkdwn", "text": incident.description or "_No description_"}},
            ],
        }
        resp = await self._client.post(self.slack_webhook_url, json=payload)
        resp.raise_for_status()
        return {"response": resp.text or "ok"}

    async def _send_pagerduty(self, incident: Incident) -> Dict[str, str]:
        if not self.pagerduty_routing_key:
            raise ValueError("PagerDuty routing key not configured")
        dedup = incident.dedup_key or hashlib.sha256(
            f"{incident.id}:{incident.severity.value}".encode()
        ).hexdigest()[:32]
        payload = {
            "routing_key": self.pagerduty_routing_key,
            "event_action": "trigger",
            "dedup_key": dedup,
            "payload": {
                "summary": f"[{incident.severity.value.upper()}] {incident.title}",
                "severity": incident.severity.value,
                "source": incident.metadata.get("source", "incident-triage"),
                "component": incident.category.value,
                "class": incident.category.value,
                "custom_details": {
                    "incident_id": incident.id,
                    "description": incident.description,
                    **incident.metadata,
                },
            },
        }
        resp = await self._client.post(self.pagerduty_api_url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return {"dedup_key": data.get("dedup_key", dedup)}

    async def _send_email(self, incident: Incident) -> Dict[str, str]:
        if not self.email_endpoint:
            raise ValueError("Email endpoint not configured")
        payload = {
            "to": incident.metadata.get("email_recipients", ["oncall@example.com"]),
            "subject": f"[{incident.severity.value.upper()}] {incident.title}",
            "body": (
                f"Incident ID: {incident.id}\n"
                f"Severity: {incident.severity.value}\n"
                f"Category: {incident.category.value}\n\n"
                f"{incident.description}"
            ),
        }
        resp = await self._client.post(self.email_endpoint, json=payload)
        resp.raise_for_status()
        return {"response": "ok"}

    async def close(self) -> None:
        await self._client.aclose()