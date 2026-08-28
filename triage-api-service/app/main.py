import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from app.models import (
    IncidentSubmit, IncidentResponse, TriageUpdate,
    Severity, IncidentStatus, ErrorResponse,
)

app = FastAPI(title="Incident Triage API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# In-memory store (replace with DB in production)
_incidents: dict[str, IncidentResponse] = {}
_dedup_index: dict[str, str] = {}
_correlation_index: dict[str, list[str]] = {}


def classify_severity(submit: IncidentSubmit) -> Severity:
    """Rule-based severity classification (swap with ML model)."""
    if submit.severity:
        return submit.severity
    env = submit.source.environment.lower()
    labels = submit.source.labels
    if env == "production" and labels.get("oncall") == "true":
        return Severity.CRITICAL
    if env == "production":
        return Severity.HIGH
    if env == "staging":
        return Severity.MEDIUM
    return Severity.LOW


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


@app.post(
    "/incidents",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    responses={409: {"model": ErrorResponse}},
)
def create_incident(body: IncidentSubmit):
    # Dedup: if dedup_key exists, return existing incident
    if body.dedup_key and body.dedup_key in _dedup_index:
        existing_id = _dedup_index[body.dedup_key]
        if existing_id in _incidents:
            return _incidents[existing_id]

    severity = classify_severity(body)
    incident_id = str(uuid.uuid4())
    ts = now_utc()
    incident = IncidentResponse(
        id=incident_id,
        title=body.title,
        description=body.description,
        source=body.source,
        severity=severity,
        status=IncidentStatus.OPEN,
        dedup_key=body.dedup_key,
        correlation_id=body.correlation_id,
        raw_alert=body.raw_alert,
        created_at=ts,
        updated_at=ts,
    )
    _incidents[incident_id] = incident
    if body.dedup_key:
        _dedup_index[body.dedup_key] = incident_id
    if body.correlation_id:
        _correlation_index.setdefault(body.correlation_id, []).append(incident_id)

    return incident


@app.get(
    "/incidents/{incident_id}",
    response_model=IncidentResponse,
    responses={404: {"model": ErrorResponse}},
)
def get_incident(incident_id: str):
    incident = _incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.patch(
    "/incidents/{incident_id}/triage",
    response_model=IncidentResponse,
    responses={404: {"model": ErrorResponse}, 422: {"model": ErrorResponse}},
)
def update_triage(incident_id: str, body: TriageUpdate):
    incident = _incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if incident.status == IncidentStatus.RESOLVED and body.status not in (
        IncidentStatus.CLOSED,
        IncidentStatus.RESOLVED,
    ):
        raise HTTPException(
            status_code=422,
            detail="Cannot change status of a resolved incident except to closed",
        )

    update_data = body.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(incident, field, value)
    incident.updated_at = now_utc()
    _incidents[incident_id] = incident
    return incident


@app.get("/incidents", response_model=list[IncidentResponse])
def list_incidents(
    severity: Optional[Severity] = None,
    status: Optional[IncidentStatus] = None,
    limit: int = 50,
    offset: int = 0,
):
    results = list(_incidents.values())
    if severity:
        results = [i for i in results if i.severity == severity]
    if status:
        results = [i for i in results if i.status == status]
    results.sort(key=lambda i: i.created_at, reverse=True)
    return results[offset : offset + limit]


@app.get("/health")
def health():
    return {"status": "ok", "incidents_count": len(_incidents)}