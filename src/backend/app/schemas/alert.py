from datetime import datetime
from typing import List, Optional, Any
from pydantic import BaseModel, ConfigDict, Field
from app.models.alert import AlertSeverity, AlertStatus, AlertSource


class AlertBase(BaseModel):
    title: str
    description: str
    source: AlertSource
    source_label: str = Field(alias="sourceLabel")
    severity: AlertSeverity
    status: AlertStatus = AlertStatus.OPEN
    risk_score: int = Field(alias="riskScore", ge=0, le=100)
    related_incident_id: Optional[str] = Field(default=None, alias="relatedIncidentId")
    mitre_techniques: List[str] = Field(default_factory=list, alias="mitreTechniques")
    indicators: List[str] = Field(default_factory=list)
    team_id: str = Field(default="t-soc-north", alias="teamId")


class AlertCreate(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: Optional[str] = None
    title: str
    description: str
    source: AlertSource
    source_label: Optional[str] = Field(default=None, alias="sourceLabel")
    severity: AlertSeverity = AlertSeverity.MEDIUM
    status: AlertStatus = AlertStatus.OPEN
    risk_score: Optional[int] = Field(default=50, alias="riskScore")
    related_incident_id: Optional[str] = Field(default=None, alias="relatedIncidentId")
    mitre_techniques: List[str] = Field(default_factory=list, alias="mitreTechniques")
    indicators: List[str] = Field(default_factory=list)
    team_id: str = Field(default="t-soc-north", alias="teamId")
    timestamp: Optional[datetime] = None
    raw_data: Optional[Any] = Field(default=None, alias="rawData")


class AlertUpdate(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[AlertSeverity] = None
    status: Optional[AlertStatus] = None
    risk_score: Optional[int] = Field(default=None, alias="riskScore")
    related_incident_id: Optional[str] = Field(default=None, alias="relatedIncidentId")
    mitre_techniques: Optional[List[str]] = Field(default=None, alias="mitreTechniques")
    indicators: Optional[List[str]] = None


class AlertRead(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        serialize_by_alias=True
    )

    id: str
    team_id: str = Field(serialization_alias="teamId", validation_alias="team_id")
    title: str
    description: str
    source: AlertSource
    source_label: str = Field(serialization_alias="sourceLabel", validation_alias="source_label")
    timestamp: datetime
    severity: AlertSeverity
    status: AlertStatus
    risk_score: int = Field(serialization_alias="riskScore", validation_alias="risk_score")
    related_incident_id: Optional[str] = Field(default=None, serialization_alias="relatedIncidentId", validation_alias="related_threat_id")
    mitre_techniques: List[str] = Field(default_factory=list, serialization_alias="mitreTechniques", validation_alias="mitre_techniques")
    indicators: List[str] = Field(default_factory=list)


class AlertBulkIngestResponse(BaseModel):
    ingested_count: int
    alert_ids: List[str]
    correlation_triggered: bool = True


class TrendPointResponse(BaseModel):
    label: str
    alerts: int
    incidents: int
