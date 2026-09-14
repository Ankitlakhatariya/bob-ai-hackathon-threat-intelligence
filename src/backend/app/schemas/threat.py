from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.models.threat import ThreatStatus, ThreatSeverity


class ThreatBase(BaseModel):
    title: str
    summary: str
    explanation: Optional[str] = None
    severity: ThreatSeverity
    status: ThreatStatus = ThreatStatus.ACTIVE
    confidence: int = Field(default=75, ge=0, le=100)
    alert_ids: List[str] = Field(default_factory=list, alias="alertIds")
    mitre_techniques: List[str] = Field(default_factory=list, alias="mitreTechniques")


class ThreatCreate(ThreatBase):
    model_config = ConfigDict(populate_by_name=True)
    id: Optional[str] = None


class ThreatUpdate(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    title: Optional[str] = None
    summary: Optional[str] = None
    explanation: Optional[str] = None
    severity: Optional[ThreatSeverity] = None
    status: Optional[ThreatStatus] = None
    confidence: Optional[int] = Field(default=None, ge=0, le=100)
    alert_ids: Optional[List[str]] = Field(default=None, alias="alertIds")
    mitre_techniques: Optional[List[str]] = Field(default=None, alias="mitreTechniques")


class ThreatRead(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        serialize_by_alias=True
    )

    id: str
    title: str
    summary: str
    explanation: Optional[str] = None
    severity: ThreatSeverity
    status: ThreatStatus
    confidence: int
    opened_at: datetime = Field(serialization_alias="openedAt", validation_alias="opened_at")
    updated_at: datetime = Field(serialization_alias="updatedAt", validation_alias="updated_at")
    alert_ids: List[str] = Field(default_factory=list, serialization_alias="alertIds", validation_alias="alert_ids")
    mitre_techniques: List[str] = Field(default_factory=list, serialization_alias="mitreTechniques", validation_alias="mitre_techniques")


class ThreatTimelineEvent(BaseModel):
    time: datetime
    label: str
    tone: str = "primary"  # primary, accent, neutral
