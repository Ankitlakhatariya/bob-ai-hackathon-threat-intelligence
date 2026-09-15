import uuid
from typing import List, Optional
from sqlalchemy import String, Text, ForeignKey, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.database import Base, TimestampMixin, StringArrayType


class BlufReport(Base, TimestampMixin):
    """Bottom Line Up Front (BLUF) brief for incident executive summaries."""
    __tablename__ = "bluf_reports"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    threat_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("threats.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )
    bottom_line: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str] = mapped_column(Text, nullable=False)
    key_evidence: Mapped[List[str]] = mapped_column(StringArrayType(), default=list, nullable=False)
    recommended_focus: Mapped[str] = mapped_column(Text, nullable=False)
    generated_by: Mapped[str] = mapped_column(String(128), default="ThreatLens Correlation Engine", nullable=False)

    # Relationships
    threat = relationship("Threat", back_populates="bluf_report")
