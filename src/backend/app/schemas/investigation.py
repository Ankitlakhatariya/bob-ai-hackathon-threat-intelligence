from uuid import UUID
from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, ConfigDict, Field, model_validator
from app.models.investigation import InvestigationStatus, InvestigationPriority


class InvestigationBase(BaseModel):
    title: Optional[str] = None
    threat_id: Optional[str] = Field(None, serialization_alias="threatId")
    alert_id: Optional[str] = Field(None, serialization_alias="alertId")
    priority: InvestigationPriority = InvestigationPriority.P2
    assigned_analyst: Optional[str] = Field(None, serialization_alias="assignedAnalyst")
    assigned_to: Optional[str] = Field(None, serialization_alias="assignedTo")
    notes: Optional[str] = None
    findings: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def sync_analyst_and_title(cls, data: Any) -> Any:
        if isinstance(data, dict):
            analyst = (
                data.get("assigned_analyst")
                or data.get("assigned_to")
                or data.get("assignedAnalyst")
                or data.get("assignedTo")
            )
            if analyst:
                data["assigned_analyst"] = analyst
                data["assigned_to"] = analyst
            if not data.get("title"):
                th_id = data.get("threat_id") or data.get("threatId")
                al_id = data.get("alert_id") or data.get("alertId")
                if th_id:
                    data["title"] = f"Investigation for Threat {th_id}"
                elif al_id:
                    data["title"] = f"Investigation for Alert {al_id}"
                else:
                    data["title"] = "Threat Investigation Case"
        return data


class InvestigationCreate(InvestigationBase):
    status: Optional[InvestigationStatus] = InvestigationStatus.OPEN


class InvestigationUpdate(BaseModel):
    title: Optional[str] = None
    threat_id: Optional[str] = Field(None, serialization_alias="threatId")
    status: Optional[InvestigationStatus] = None
    priority: Optional[InvestigationPriority] = None
    assigned_analyst: Optional[str] = Field(None, serialization_alias="assignedAnalyst")
    assigned_to: Optional[str] = Field(None, serialization_alias="assignedTo")
    notes: Optional[str] = None
    findings: Optional[str] = None
    resolution_summary: Optional[str] = Field(None, serialization_alias="resolutionSummary")

    @model_validator(mode="before")
    @classmethod
    def sync_analyst(cls, data: Any) -> Any:
        if isinstance(data, dict):
            analyst = (
                data.get("assigned_analyst")
                or data.get("assigned_to")
                or data.get("assignedAnalyst")
                or data.get("assignedTo")
            )
            if analyst:
                data["assigned_analyst"] = analyst
                data["assigned_to"] = analyst
        return data


class InvestigationNoteCreate(BaseModel):
    note: str
    author: Optional[str] = "Analyst"


class InvestigationResolveRequest(BaseModel):
    resolution_summary: Optional[str] = Field(
        "Threat mitigated and affected assets isolated.",
        serialization_alias="resolutionSummary",
    )


class InvestigationFalsePositiveRequest(BaseModel):
    reason: Optional[str] = "Activity verified as benign authorized administrative task."
    evidence_notes: Optional[str] = Field(None, serialization_alias="evidenceNotes")


class InvestigationEscalateRequest(BaseModel):
    escalate_to: Optional[str] = Field("P1", serialization_alias="escalateTo")
    reason: Optional[str] = "Immediate containment and escalation required."


class InvestigationRead(InvestigationBase):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: UUID
    investigation_id: str = Field(..., serialization_alias="investigationId")
    status: InvestigationStatus
    resolution_summary: Optional[str] = Field(None, serialization_alias="resolutionSummary")
    timeline_events: Optional[List[Any]] = Field(default_factory=list, serialization_alias="timelineEvents")
    created_at: datetime = Field(..., serialization_alias="createdAt")
    updated_at: datetime = Field(..., serialization_alias="updatedAt")
    closed_at: Optional[datetime] = Field(None, serialization_alias="closedAt")

    @model_validator(mode="before")
    @classmethod
    def populate_computed_fields(cls, data: Any) -> Any:
        if hasattr(data, "id"):
            inv_id = str(data.id)
            analyst = getattr(data, "assigned_to", None)
            return {
                "id": data.id,
                "investigation_id": inv_id,
                "title": getattr(data, "title", ""),
                "threat_id": getattr(data, "threat_id", None),
                "alert_id": getattr(data, "alert_id", None),
                "status": getattr(data, "status", InvestigationStatus.OPEN),
                "priority": getattr(data, "priority", InvestigationPriority.P2),
                "assigned_analyst": analyst,
                "assigned_to": analyst,
                "notes": getattr(data, "notes", None),
                "findings": getattr(data, "findings", None),
                "resolution_summary": getattr(data, "resolution_summary", None),
                "timeline_events": getattr(data, "timeline_events", []),
                "created_at": getattr(data, "created_at", None),
                "updated_at": getattr(data, "updated_at", None),
                "closed_at": getattr(data, "closed_at", None),
            }
        elif isinstance(data, dict):
            if "id" in data and "investigation_id" not in data:
                data["investigation_id"] = str(data["id"])
            analyst = data.get("assigned_analyst") or data.get("assigned_to")
            data["assigned_analyst"] = analyst
            data["assigned_to"] = analyst
        return data

