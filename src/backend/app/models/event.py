import uuid
from datetime import datetime, timezone
from typing import Optional, Any, List
from sqlalchemy import String, Text, Integer, DateTime, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.database import Base, TimestampMixin


class Event(Base, TimestampMixin):
    """Normalized security telemetry event from ingestion."""
    __tablename__ = "events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    event_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), index=True, nullable=True)
    destination_ip: Mapped[Optional[str]] = mapped_column(String(45), index=True, nullable=True)
    source_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), index=True, nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), index=True, nullable=True)
    domain: Mapped[Optional[str]] = mapped_column(String(255), index=True, nullable=True)
    file_hash: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    process_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    command_line: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    indicators: Mapped[List[str]] = mapped_column(ARRAY(String), default=list, nullable=False)
    metadata_info: Mapped[Optional[Any]] = mapped_column(JSONB, nullable=True)
    raw_data: Mapped[Optional[Any]] = mapped_column(JSONB, nullable=True)

    # Relationships
    alert = relationship("Alert", back_populates="events")


Index("idx_events_network", Event.source_ip, Event.destination_ip)
Index("idx_events_endpoint", Event.hostname, Event.username, Event.file_hash)
