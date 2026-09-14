import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from sqlalchemy import String, Integer, DateTime, Enum as SQLEnum, Index
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import Mapped, mapped_column
from app.database.database import Base, TimestampMixin


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    CVE = "cve"
    EMAIL = "email"


class IndicatorReputation(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class Indicator(Base, TimestampMixin):
    """Threat intelligence indicator (IOC)."""
    __tablename__ = "indicators"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    indicator_value: Mapped[str] = mapped_column(String(512), unique=True, index=True, nullable=False)
    indicator_type: Mapped[IndicatorType] = mapped_column(
        SQLEnum(IndicatorType, name="indicator_type_enum", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        index=True,
    )
    threat_type: Mapped[str] = mapped_column(String(128), default="generic_threat", nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=80, nullable=False)  # 0-100
    reputation: Mapped[IndicatorReputation] = mapped_column(
        SQLEnum(IndicatorReputation, name="indicator_reputation_enum", values_callable=lambda x: [e.value for e in x]),
        default=IndicatorReputation.SUSPICIOUS,
        nullable=False,
        index=True,
    )
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
    source: Mapped[str] = mapped_column(String(128), default="internal_enrichment", nullable=False)
    tags: Mapped[List[str]] = mapped_column(ARRAY(String), default=list, nullable=False)


Index("idx_indicators_lookup", Indicator.indicator_value, Indicator.reputation)
