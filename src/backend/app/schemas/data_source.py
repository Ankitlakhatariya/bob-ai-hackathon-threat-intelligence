from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict
from app.models.data_source import DataSourceStatus


class DataSourceBase(BaseModel):
    id: str
    name: str
    source_type: str = "sensor"
    detail: str
    health: DataSourceStatus = DataSourceStatus.HEALTHY
    lag_seconds: Optional[int] = 0


class DataSourceCreate(DataSourceBase):
    pass


class DataSourceUpdate(BaseModel):
    name: Optional[str] = None
    detail: Optional[str] = None
    health: Optional[DataSourceStatus] = None
    lag_seconds: Optional[int] = None


class DataSourceRead(DataSourceBase):
    model_config = ConfigDict(from_attributes=True)

    last_heartbeat: datetime
    created_at: datetime
    updated_at: datetime
