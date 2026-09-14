from typing import List, Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict


class MitreTacticRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str] = None


class MitreTechniqueRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    tactics: List[str]
    description: str
    url: str


class ThreatMitreRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    threat_id: str
    technique_id: str
    confidence: int
    evidence: Optional[str] = None
    technique: Optional[MitreTechniqueRead] = None
