from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.models.threat import ThreatStatus, ThreatSeverity


class ThreatBase(BaseModel):
    title: str
    summary: str
    description: Optional[str] = None
    explanation: Optional[str] = None
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    status: ThreatStatus = ThreatStatus.ACTIVE
    risk_score: int = Field(default=50, alias="riskScore")
    confidence: int = Field(default=75, ge=0, le=100)
    alert_count: int = Field(default=1, alias="alertCount")
    affected_assets: List[str] = Field(default_factory=list, alias="affectedAssets")
    alert_ids: List[str] = Field(default_factory=list, alias="alertIds")
    mitre_techniques: List[str] = Field(default_factory=list, alias="mitreTechniques")


class ThreatCreate(ThreatBase):
    model_config = ConfigDict(populate_by_name=True)
    id: Optional[str] = None
    threat_id: Optional[str] = Field(default=None, alias="threatId")


class ThreatUpdate(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    title: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    explanation: Optional[str] = None
    severity: Optional[ThreatSeverity] = None
    status: Optional[ThreatStatus] = None
    risk_score: Optional[int] = Field(default=None, alias="riskScore")
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
    threat_id: Optional[str] = Field(default=None, serialization_alias="threatId", validation_alias="threat_id")
    title: str
    summary: str
    description: Optional[str] = None
    explanation: Optional[str] = None
    severity: ThreatSeverity
    status: ThreatStatus
    risk_score: int = Field(default=50, serialization_alias="riskScore", validation_alias="risk_score")
    confidence: int
    alert_count: int = Field(default=1, serialization_alias="alertCount", validation_alias="alert_count")
    affected_assets: List[str] = Field(default_factory=list, serialization_alias="affectedAssets", validation_alias="affected_assets")
    first_seen: datetime = Field(serialization_alias="firstSeen", validation_alias="first_seen")
    last_seen: datetime = Field(serialization_alias="lastSeen", validation_alias="last_seen")

    # Frontend backward compatibility fields
    opened_at: datetime = Field(serialization_alias="openedAt", validation_alias="opened_at")
    updated_at: datetime = Field(serialization_alias="updatedAt", validation_alias="updated_at")
    alert_ids: List[str] = Field(default_factory=list, serialization_alias="alertIds", validation_alias="alert_ids")
    mitre_techniques: List[str] = Field(default_factory=list, serialization_alias="mitreTechniques", validation_alias="mitre_techniques")


class ThreatTimelineEvent(BaseModel):
    time: datetime
    label: str
    tone: str = "primary"  # primary, accent, neutral
