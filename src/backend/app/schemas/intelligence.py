from uuid import UUID
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict
from app.models.indicator import IndicatorType, IndicatorReputation


class IndicatorBase(BaseModel):
    indicator_value: str
    indicator_type: IndicatorType
    threat_type: str = "generic_threat"
    confidence: int = 80
    reputation: IndicatorReputation = IndicatorReputation.SUSPICIOUS
    source: str = "threat_feed"
    tags: List[str] = []


class IndicatorCreate(IndicatorBase):
    pass


class IndicatorRead(IndicatorBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    first_seen: datetime
    last_seen: datetime
    created_at: datetime


class IndicatorLookupResponse(BaseModel):
    indicator: str
    found: bool
    reputation: IndicatorReputation
    confidence: int
    threat_type: Optional[str] = None
    source: Optional[str] = None
    tags: List[str] = []
    associated_alerts: List[str] = []
