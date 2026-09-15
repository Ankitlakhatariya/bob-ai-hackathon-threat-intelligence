from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from sqlalchemy import String, Integer, DateTime, Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column
from app.database.database import Base, TimestampMixin


class DataSourceStatus(str, Enum):
    HEALTHY = "healthy"
    OPERATIONAL = "operational"
    DEGRADED = "degraded"
    OFFLINE = "offline"


class DataSource(Base, TimestampMixin):
    """Monitored data source feed matching frontend SystemStatus."""
    __tablename__ = "data_sources"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. siem, edr, network
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), default="sensor", nullable=False)
    detail: Mapped[str] = mapped_column(String(255), nullable=False)
    health: Mapped[DataSourceStatus] = mapped_column(
        SQLEnum(DataSourceStatus, native_enum=False, name="data_source_status_enum", values_callable=lambda x: [e.value for e in x]),
        default=DataSourceStatus.HEALTHY,
        nullable=False,
    )
    lag_seconds: Mapped[Optional[int]] = mapped_column(Integer, default=0, nullable=True)
    last_heartbeat: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
