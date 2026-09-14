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
    """Represents a correlated incident / threat campaign grouping related alerts."""
    __tablename__ = "threats"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. INC-1001 or THREAT-1001
    threat_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
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
    risk_score: Mapped[int] = mapped_column(Integer, default=50, nullable=False, index=True)  # 0-100
    confidence: Mapped[int] = mapped_column(Integer, default=70, nullable=False)  # 0-100
    alert_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    affected_assets: Mapped[List[str]] = mapped_column(ARRAY(String), default=list, nullable=False)
    scoring_factors: Mapped[Optional[Any]] = mapped_column(JSONB, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Legacy fields preserved for frontend compatibility
    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at_custom: Mapped[datetime] = mapped_column(
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
Index("idx_threats_timeline", Threat.first_seen, Threat.last_seen)
Index("idx_threats_risk_score", Threat.risk_score.desc())
