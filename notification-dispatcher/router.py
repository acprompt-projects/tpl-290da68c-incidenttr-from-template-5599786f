import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from .dispatcher import (
    Category, Channel, Incident, NotificationDispatcher, RateLimiter, RoutingRule, Severity,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/notifications", tags=["notifications"])

_dispatcher: Optional[NotificationDispatcher] = None


def init_dispatcher(
    slack_webhook_url: Optional[str] = None,
    pagerduty_routing_key: Optional[str] = None,
    pagerduty_api_url: str = "https://events.pagerduty.com/v2/enqueue",
    email_endpoint: Optional[str] = None,
    routing_rules: Optional[List[RoutingRule]] = None,
) -> NotificationDispatcher:
    global _dispatcher
    _dispatcher = NotificationDispatcher(
        slack_webhook_url=slack_webhook_url,
        pagerduty_routing_key=pagerduty_routing_key,
        pagerduty_api_url=pagerduty_api_url,
        email_endpoint=email_endpoint,
        routing_rules=routing_rules,
    )
    return _dispatcher


def get_dispatcher() -> NotificationDispatcher:
    if _dispatcher is None:
        return init_dispatcher()
    return _dispatcher


class IncidentPayload(BaseModel):
    id: str
    title: str
    severity: Severity
    category: Category
    description: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    dedup_key: Optional[str] = None


class RoutingRulePayload(BaseModel):
    channels: List[Channel]
    severities: List[Severity] = Field(default_factory=list)
    categories: List[Category] = Field(default_factory=list)


class DispatchResponse(BaseModel):
    incident_id: str
    dispatch: Dict[str, Any]


class PreviewResponse(BaseModel):
    incident_id: str
    channels: List[str]


class ConfigPayload(BaseModel):
    slack_webhook_url: Optional[str] = None
    pagerduty_routing_key: Optional[str] = None
    email_endpoint: Optional[str] = None


@router.post("/dispatch", response_model=DispatchResponse)
async def dispatch_incident(payload: IncidentPayload):
    disp = get_dispatcher()
    incident = Incident(
        id=payload.id,
        title=payload.title,
        severity=payload.severity,
        category=payload.category,
        description=payload.description,
        metadata=payload.metadata,
        dedup_key=payload.dedup_key,
    )
    result = await disp.dispatch(incident)
    if all(v.get("status") == "error" for v in result["dispatch"].values()):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=result)
    return result


@router.post("/preview", response_model=PreviewResponse)
async def preview_channels(payload: IncidentPayload):
    disp = get_dispatcher()
    incident = Incident(
        id=payload.id, title=payload.title, severity=payload.severity,
        category=payload.category, description=payload.description,
        metadata=payload.metadata, dedup_key=payload.dedup_key,
    )
    channels = disp.resolve_channels(incident)
    return {"incident_id": incident.id, "channels": [c.value for c in channels]}


@router.put("/routing-rules")
async def update_routing_rules(rules: List[RoutingRulePayload]):
    disp = get_dispatcher()
    disp.routing_rules = [
        RoutingRule(channels=r.channels, severities=r.severities, categories=r.categories)
        for r in rules
    ]
    return {"status": "updated", "rule_count": len(disp.routing_rules)}


@router.get("/routing-rules")
async def get_routing_rules():
    disp = get_dispatcher()
    return [
        {"channels": [c.value for c in rule.channels],
         "severities": [s.value for s in rule.severities],
         "categories": [c.value for c in rule.categories]}
        for rule in disp.routing_rules
    ]


@router.put("/config")
async def update_config(config: ConfigPayload):
    disp = get_dispatcher()
    if config.slack_webhook_url is not None:
        disp.slack_webhook_url = config.slack_webhook_url
    if config.pagerduty_routing_key is not None:
        disp.pagerduty_routing_key = config.pagerduty_routing_key
    if config.email_endpoint is not None:
        disp.email_endpoint = config.email_endpoint
    return {"status": "updated"}