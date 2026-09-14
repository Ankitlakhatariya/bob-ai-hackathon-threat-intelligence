from pydantic import BaseModel, ConfigDict
from typing import Optional, Dict, Any, Union
from datetime import datetime
from app.models.alert import AlertSeverity
from app.models.threat import ThreatSeverity, ThreatStatus


class BaseWSEvent(BaseModel):
    event_type: str
    timestamp: datetime


class AlertWSData(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    alert_id: str
    severity: AlertSeverity
    source: str
    event_type: Optional[str] = None
    timestamp: datetime


class AlertWSEvent(BaseWSEvent):
    data: AlertWSData


class ThreatWSData(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    threat_id: str
    title: str
    severity: ThreatSeverity
    risk_score: int
    confidence: float
    status: ThreatStatus
    alert_count: int


class ThreatWSEvent(BaseWSEvent):
    data: ThreatWSData


class InvestigationWSData(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    investigation_id: str
    threat_id: Optional[str] = None
    status: str
    priority: str


class InvestigationWSEvent(BaseWSEvent):
    data: InvestigationWSData


class IntelligenceWSData(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    indicator_value: str
    threat_actor: Optional[str] = None
    matched_alert_ids: list[str]


class IntelligenceWSEvent(BaseWSEvent):
    data: IntelligenceWSData


WebSocketPayload = Union[AlertWSEvent, ThreatWSEvent, InvestigationWSEvent, IntelligenceWSEvent]
