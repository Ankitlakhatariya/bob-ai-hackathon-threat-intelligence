from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Any
from sqlalchemy import String, Text, Integer, DateTime, ForeignKey, Enum as SQLEnum, Index
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.database import Base, TimestampMixin


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AlertStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false-positive"


class AlertSource(str, Enum):
    SIEM = "siem"
    EDR = "edr"
    NETWORK_SENSOR = "network-sensor"
    THREAT_FEED = "threat-feed"


class Alert(Base, TimestampMixin):
    """Core Alert entity matching frontend Alert interface with enriched telemetry fields."""
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # e.g. ALERT-2041
    team_id: Mapped[str] = mapped_column(String(64), default="t-soc-north", nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[AlertSource] = mapped_column(
        SQLEnum(AlertSource, native_enum=False, name="alert_source_enum", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        index=True,
    )
    source_label: Mapped[str] = mapped_column(String(128), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    severity: Mapped[AlertSeverity] = mapped_column(
        SQLEnum(AlertSeverity, native_enum=False, name="alert_severity_enum", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        index=True,
    )
    status: Mapped[AlertStatus] = mapped_column(
        SQLEnum(AlertStatus, native_enum=False, name="alert_status_enum", values_callable=lambda x: [e.value for e in x]),
        default=AlertStatus.OPEN,
        nullable=False,
        index=True,
    )
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, index=True)  # 0-100
    related_threat_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        ForeignKey("threats.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    mitre_techniques: Mapped[List[str]] = mapped_column(ARRAY(String), default=list, nullable=False)
    indicators: Mapped[List[str]] = mapped_column(ARRAY(String), default=list, nullable=False)
    raw_data: Mapped[Optional[Any]] = mapped_column(JSONB, nullable=True)

    # Ingestion telemetry & normalized fields for fast indexed filtering
    event_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    metadata_info: Mapped[Optional[Any]] = mapped_column(JSONB, nullable=True)

    # Relationships
    threat = relationship("Threat", back_populates="alerts", foreign_keys=[related_threat_id])
    events = relationship("Event", back_populates="alert", cascade="all, delete-orphan")


Index("idx_alerts_status_severity", Alert.status, Alert.severity)
Index("idx_alerts_source_timestamp", Alert.source, Alert.timestamp)
Index("idx_alerts_risk_score", Alert.risk_score.desc())
Index("idx_alerts_ip_lookup", Alert.source_ip, Alert.destination_ip)
Index("idx_alerts_host_user", Alert.hostname, Alert.username)
