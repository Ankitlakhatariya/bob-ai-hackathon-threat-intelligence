import uuid
from typing import Optional, Any
from sqlalchemy import String, Text, Index, Uuid
from sqlalchemy.orm import Mapped, mapped_column
from app.database.database import Base, TimestampMixin, JsonDataType


class AuditLog(Base, TimestampMixin):
    """Immutable audit trail of sensitive system actions and analyst operations."""
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    action: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    entity_id: Mapped[Optional[str]] = mapped_column(String(128), index=True, nullable=True)
    details: Mapped[Optional[Any]] = mapped_column(JsonDataType(), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)


Index("idx_audit_logs_action_created", AuditLog.action, AuditLog.created_at)
Index("idx_audit_logs_entity", AuditLog.entity_type, AuditLog.entity_id)
