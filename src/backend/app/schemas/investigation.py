from uuid import UUID
from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, ConfigDict
from app.models.investigation import InvestigationStatus, InvestigationPriority


class InvestigationBase(BaseModel):
    title: str
    threat_id: Optional[str] = None
    alert_id: Optional[str] = None
    priority: InvestigationPriority = InvestigationPriority.P2
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    findings: Optional[str] = None


class InvestigationCreate(InvestigationBase):
    pass


class InvestigationUpdate(BaseModel):
    title: Optional[str] = None
    status: Optional[InvestigationStatus] = None
    priority: Optional[InvestigationPriority] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    findings: Optional[str] = None
    resolution_summary: Optional[str] = None


class InvestigationNoteCreate(BaseModel):
    note: str
    author: Optional[str] = "Analyst"


class InvestigationRead(InvestigationBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: InvestigationStatus
    resolution_summary: Optional[str] = None
    timeline_events: Optional[List[Any]] = None
    created_at: datetime
    updated_at: datetime
