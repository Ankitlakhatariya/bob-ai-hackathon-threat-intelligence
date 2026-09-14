from uuid import UUID
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict


class CorrelationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    alert_id: str
    related_alert_id: str
    threat_id: Optional[str] = None
    correlation_reason: str
    correlation_score: float
    rule_name: str
    created_at: datetime


class CorrelationResult(BaseModel):
    correlated_incidents_created: int
    correlations_identified: int
    alerts_processed: int
    details: List[str] = []
