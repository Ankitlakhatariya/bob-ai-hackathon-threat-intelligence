import uuid
from enum import Enum
from typing import Optional, List, Any
from sqlalchemy import String, Text, ForeignKey, Enum as SQLEnum, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.database import Base, TimestampMixin


class InvestigationStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class InvestigationPriority(str, Enum):
    P1 = "P1"  # Critical — act immediately
    P2 = "P2"  # High — investigate today
    P3 = "P3"  # Medium — priority review
    P4 = "P4"  # Low — routine review


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
        SQLEnum(InvestigationStatus, name="investigation_status_enum", values_callable=lambda x: [e.value for e in x]),
        default=InvestigationStatus.OPEN,
        nullable=False,
        index=True,
    )
    priority: Mapped[InvestigationPriority] = mapped_column(
        SQLEnum(InvestigationPriority, name="investigation_priority_enum", values_callable=lambda x: [e.value for e in x]),
        default=InvestigationPriority.P2,
        nullable=False,
        index=True,
    )
    assigned_to: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    findings: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    resolution_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timeline_events: Mapped[Optional[Any]] = mapped_column(JSONB, default=list, nullable=True)

    # Relationships
    threat = relationship("Threat", back_populates="investigations")


Index("idx_investigations_status_priority", Investigation.status, Investigation.priority)
