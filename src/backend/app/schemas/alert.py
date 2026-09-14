from datetime import datetime
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, ConfigDict, Field
from app.models.alert import AlertSeverity, AlertStatus, AlertSource


class AlertCreate(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    id: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    source: Optional[AlertSource] = None
    source_label: Optional[str] = Field(default=None, alias="sourceLabel")
    source_type: Optional[str] = Field(default=None, alias="sourceType")
    severity: Optional[AlertSeverity] = None
    status: AlertStatus = AlertStatus.OPEN
    risk_score: Optional[int] = Field(default=None, alias="riskScore")
    related_incident_id: Optional[str] = Field(default=None, alias="relatedIncidentId")
    mitre_techniques: List[str] = Field(default_factory=list, alias="mitreTechniques")
    indicators: List[str] = Field(default_factory=list)
    team_id: str = Field(default="t-soc-north", alias="teamId")
    timestamp: Optional[datetime] = None

    # Telemetry fields supported directly
    event_type: Optional[str] = Field(default=None, alias="eventType")
    source_ip: Optional[str] = Field(default=None, alias="sourceIp")
    destination_ip: Optional[str] = Field(default=None, alias="destinationIp")
    source_port: Optional[int] = Field(default=None, alias="sourcePort")
    destination_port: Optional[int] = Field(default=None, alias="destinationPort")
    protocol: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    domain: Optional[str] = None
    file_hash: Optional[str] = Field(default=None, alias="fileHash")
    process_name: Optional[str] = Field(default=None, alias="processName")
    command_line: Optional[str] = Field(default=None, alias="commandLine")
    url: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = Field(default=None, alias="rawData")
    metadata: Optional[Dict[str, Any]] = None


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

    # Normalized fields exposed to analysts
    event_type: Optional[str] = Field(default=None, serialization_alias="eventType", validation_alias="event_type")
    source_ip: Optional[str] = Field(default=None, serialization_alias="sourceIp", validation_alias="source_ip")
    destination_ip: Optional[str] = Field(default=None, serialization_alias="destinationIp", validation_alias="destination_ip")
    hostname: Optional[str] = None
    username: Optional[str] = None
    raw_data: Optional[Any] = Field(default=None, serialization_alias="rawData", validation_alias="raw_data")


class AlertBulkIngestResponse(BaseModel):
    ingested_count: int
    alert_ids: List[str]
    correlation_triggered: bool = True


class TrendPointResponse(BaseModel):
    label: str
    alerts: int
    incidents: int
