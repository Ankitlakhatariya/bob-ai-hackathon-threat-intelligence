from typing import List, Optional
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class MitreTacticRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str] = None


class MitreTechniqueRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: str
    name: str
    tactics: List[str]
    description: str
    url: str
    is_subtechnique: bool = Field(default=False, serialization_alias="isSubtechnique")
    parent_technique_id: Optional[str] = Field(default=None, serialization_alias="parentTechniqueId")


class ThreatMitreMappingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: Optional[UUID] = None
    threat_id: str = Field(serialization_alias="threatId")
    technique_id: str = Field(serialization_alias="techniqueId")
    technique_name: str = Field(serialization_alias="techniqueName")
    tactic: str
    confidence: int
    evidence: str
    source: str
    created_at: Optional[datetime] = Field(default=None, serialization_alias="createdAt")


ThreatMitreRead = ThreatMitreMappingRead
