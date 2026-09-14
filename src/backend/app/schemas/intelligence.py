from uuid import UUID
from datetime import datetime
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, ConfigDict, Field
from app.models.indicator import IndicatorType, IndicatorReputation


class IndicatorBase(BaseModel):
    indicator: str
    indicator_type: IndicatorType = Field(alias="indicator_type")
    reputation: IndicatorReputation = IndicatorReputation.UNKNOWN
    confidence: int = Field(default=50, ge=0, le=100)
    source: str = "threat_feed"
    tags: List[str] = Field(default_factory=list)
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    threat_type: Optional[str] = "general_threat"
    raw_intelligence: Optional[Dict[str, Any]] = None


class IndicatorCreate(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    indicator: str
    indicator_type: Optional[IndicatorType] = None  # Auto-detected if omitted!
    reputation: IndicatorReputation = IndicatorReputation.UNKNOWN
    confidence: int = Field(default=50, ge=0, le=100)
    source: str = "internal_analyst"
    tags: List[str] = Field(default_factory=list)
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    threat_type: Optional[str] = "general_threat"
    raw_intelligence: Optional[Dict[str, Any]] = None


class IndicatorRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: UUID
    indicator: str
    indicator_type: IndicatorType
    reputation: IndicatorReputation
    confidence: int
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    threat_type: Optional[str] = None
    raw_intelligence: Optional[Any] = None
    created_at: datetime


class IndicatorLookupResponse(BaseModel):
    indicator: str
    indicator_type: IndicatorType
    found: bool
    reputation: IndicatorReputation
    confidence: int
    source: str
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    threat_type: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    raw_intelligence: Optional[Any] = None
    associated_alerts: List[str] = Field(default_factory=list)
