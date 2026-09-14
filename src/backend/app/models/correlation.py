import uuid
from typing import Optional
from sqlalchemy import String, Text, Float, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
from app.database.database import Base, TimestampMixin


class Correlation(Base, TimestampMixin):
    """Stores deterministic correlation links between alerts and threats."""
    __tablename__ = "correlations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    related_alert_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    threat_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        ForeignKey("threats.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    correlation_reason: Mapped[str] = mapped_column(Text, nullable=False)
    correlation_score: Mapped[float] = mapped_column(Float, nullable=False)  # 0.0 to 1.0
    rule_name: Mapped[str] = mapped_column(String(128), default="deterministic_rule", nullable=False)


Index("idx_correlations_pair", Correlation.alert_id, Correlation.related_alert_id)
Index("idx_correlations_score", Correlation.correlation_score.desc())
