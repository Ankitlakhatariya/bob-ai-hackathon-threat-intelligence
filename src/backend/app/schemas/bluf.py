from typing import List, Optional
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field


class BlufReportRead(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        serialize_by_alias=True
    )

    bottom_line: str = Field(serialization_alias="bottomLine", validation_alias="bottom_line")
    impact: str
    key_evidence: List[str] = Field(default_factory=list, serialization_alias="keyEvidence", validation_alias="key_evidence")
    recommended_focus: str = Field(serialization_alias="recommendedFocus", validation_alias="recommended_focus")


class BlufGenerateRequest(BaseModel):
    threat_id: str
    include_timeline: bool = True
