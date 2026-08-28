from enum import Enum
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(str, Enum):
    OPEN = "open"
    TRIAGING = "triaging"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    CLOSED = "closed"


class AlertSource(BaseModel):
    service: str
    environment: str
    host: Optional[str] = None
    labels: dict[str, str] = Field(default_factory=dict)


class IncidentSubmit(BaseModel):
    title: str
    description: str
    source: AlertSource
    severity: Optional[Severity] = None
    dedup_key: Optional[str] = None
    correlation_id: Optional[str] = None
    raw_alert: Optional[dict] = None


class TriageUpdate(BaseModel):
    severity: Optional[Severity] = None
    status: Optional[IncidentStatus] = None
    assignee: Optional[str] = None
    notes: Optional[str] = None
    routing_destination: Optional[str] = None


class IncidentResponse(BaseModel):
    id: str
    title: str
    description: str
    source: AlertSource
    severity: Severity
    status: IncidentStatus
    assignee: Optional[str] = None
    notes: Optional[str] = None
    dedup_key: Optional[str] = None
    correlation_id: Optional[str] = None
    routing_destination: Optional[str] = None
    raw_alert: Optional[dict] = None
    created_at: datetime
    updated_at: datetime


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None