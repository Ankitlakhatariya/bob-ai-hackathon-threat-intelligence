from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import String, Text, Integer, DateTime, ForeignKey, Float
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.database import Base, TimestampMixin


class LLMAnalysis(Base, TimestampMixin):
    """Stores OpenAI LLM threat analysis and structured responses."""
    __tablename__ = "llm_analysis"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    threat_id: Mapped[str] = mapped_column(String(64), ForeignKey("threats.id", ondelete="CASCADE"), index=True, nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(64), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    output: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)

    # Relationships
    threat = relationship("Threat", backref="llm_analyses")
