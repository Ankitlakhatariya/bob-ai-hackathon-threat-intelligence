import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Any
from sqlalchemy import String, Integer, DateTime, Enum as SQLEnum, Index
from sqlalchemy.dialects.postgresql import UUID, ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from app.database.database import Base, TimestampMixin


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    MALWARE = "malware"


class IndicatorReputation(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class Indicator(Base, TimestampMixin):
    """Threat intelligence Indicator of Compromise (IOC)."""
    __tablename__ = "indicators"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    indicator: Mapped[str] = mapped_column(String(512), unique=True, index=True, nullable=False)
    indicator_type: Mapped[IndicatorType] = mapped_column(
        SQLEnum(IndicatorType, native_enum=False, name="indicator_type_enum", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        index=True,
    )
    reputation: Mapped[IndicatorReputation] = mapped_column(
        SQLEnum(IndicatorReputation, native_enum=False, name="indicator_reputation_enum", values_callable=lambda x: [e.value for e in x]),
        default=IndicatorReputation.UNKNOWN,
        nullable=False,
        index=True,
    )
    confidence: Mapped[int] = mapped_column(Integer, default=50, nullable=False)  # 0-100
    source: Mapped[str] = mapped_column(String(128), default="internal_feed", nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    tags: Mapped[List[str]] = mapped_column(ARRAY(String), default=list, nullable=False)
    threat_actor: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    campaign: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    threat_type: Mapped[str] = mapped_column(String(128), default="general_threat", nullable=False)
    raw_intelligence: Mapped[Optional[Any]] = mapped_column(JSONB, nullable=True)


Index("idx_indicators_search", Indicator.indicator, Indicator.indicator_type, Indicator.reputation)
Index("idx_indicators_actor_campaign", Indicator.threat_actor, Indicator.campaign)
