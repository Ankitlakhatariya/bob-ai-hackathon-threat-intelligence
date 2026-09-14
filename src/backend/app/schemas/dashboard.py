from typing import List
from pydantic import BaseModel, ConfigDict, Field
from app.models.alert import AlertSeverity
from app.models.data_source import DataSourceStatus


class DashboardOverview(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        serialize_by_alias=True
    )

    total_open: int = Field(serialization_alias="totalOpen", validation_alias="total_open")
    critical: int
    incident_count: int = Field(serialization_alias="incidentCount", validation_alias="incident_count")
    false_positive_review: int = Field(serialization_alias="falsePositiveReview", validation_alias="false_positive_review")


class SeverityDistributionItem(BaseModel):
    severity: AlertSeverity
    count: int


class SystemStatusItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    detail: str
    health: DataSourceStatus
