import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Any
from sqlalchemy import String, Text, DateTime, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym
from app.database.database import Base, TimestampMixin


class InvestigationStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CLOSED = "CLOSED"

    @classmethod
    def _missing_(cls, value: object):
        if isinstance(value, str):
            val_norm = value.upper().replace("-", "_")
            for member in cls:
                if member.value == val_norm or member.name == val_norm:
                    return member
        return None


class InvestigationPriority(str, Enum):
    P1 = "P1"  # Critical — act immediately
    P2 = "P2"  # High — investigate today
    P3 = "P3"  # Medium — priority review
    P4 = "P4"  # Low — routine review

    @classmethod
    def _missing_(cls, value: object):
        if isinstance(value, str):
            val_upper = value.upper()
            mapping = {
                "CRITICAL": cls.P1,
                "HIGH": cls.P2,
                "MEDIUM": cls.P3,
                "LOW": cls.P4,
            }
            if val_upper in mapping:
                return mapping[val_upper]
            for member in cls:
                if member.value == val_upper:
                    return member
        return None


class Investigation(Base, TimestampMixin):
    """Investigation case tracking for SOC analysts."""
    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        ForeignKey("threats.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    alert_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        ForeignKey("alerts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[InvestigationStatus] = mapped_column(
        String(32),
        default=InvestigationStatus.OPEN,
        nullable=False,
        index=True,
    )
    priority: Mapped[InvestigationPriority] = mapped_column(
        String(16),
        default=InvestigationPriority.P2,
        nullable=False,
        index=True,
    )
    assigned_to: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    findings: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    resolution_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timeline_events: Mapped[Optional[Any]] = mapped_column(JSONB, default=list, nullable=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Synonym so queries like Investigation.assigned_analyst work identically
    assigned_analyst = synonym("assigned_to")

    @property
    def investigation_id(self) -> str:
        return str(self.id)

    # Relationships
    threat = relationship("Threat", back_populates="investigations")


Index("idx_investigations_status_priority", Investigation.status, Investigation.priority)
Index("idx_investigations_threat_id", Investigation.threat_id)
Index("idx_investigations_assigned_to", Investigation.assigned_to)

