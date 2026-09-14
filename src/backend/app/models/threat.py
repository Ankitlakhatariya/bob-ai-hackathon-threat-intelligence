from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from sqlalchemy import String, Text, Integer, DateTime, Enum as SQLEnum, Index
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.database import Base, TimestampMixin


class ThreatStatus(str, Enum):
    ACTIVE = "active"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


class ThreatSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Threat(Base, TimestampMixin):
    """Represents a correlated incident / threat campaign."""
    __tablename__ = "threats"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. INC-1001
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[ThreatSeverity] = mapped_column(
        SQLEnum(ThreatSeverity, name="threat_severity_enum", values_callable=lambda x: [e.value for e in x]),
        default=ThreatSeverity.MEDIUM,
        nullable=False,
        index=True,
    )
    status: Mapped[ThreatStatus] = mapped_column(
        SQLEnum(ThreatStatus, name="threat_status_enum", values_callable=lambda x: [e.value for e in x]),
        default=ThreatStatus.ACTIVE,
        nullable=False,
        index=True,
    )
    confidence: Mapped[int] = mapped_column(Integer, default=70, nullable=False)  # 0-100
    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at_field: Mapped[datetime] = mapped_column(
        "updated_at_custom",
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    alert_ids: Mapped[List[str]] = mapped_column(ARRAY(String), default=list, nullable=False)
    mitre_techniques: Mapped[List[str]] = mapped_column(ARRAY(String), default=list, nullable=False)

    # Relationships
    alerts = relationship("Alert", back_populates="threat", foreign_keys="[Alert.related_threat_id]")
    bluf_report = relationship("BlufReport", back_populates="threat", uselist=False, cascade="all, delete-orphan")
    investigations = relationship("Investigation", back_populates="threat")


Index("idx_threats_status_severity", Threat.status, Threat.severity)
Index("idx_threats_created_at", Threat.created_at)
