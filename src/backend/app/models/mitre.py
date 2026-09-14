import uuid
from typing import List, Optional
from sqlalchemy import String, Text, Integer, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import Mapped, mapped_column
from app.database.database import Base, TimestampMixin


class MitreTactic(Base, TimestampMixin):
    """MITRE ATT&CK Tactic definition."""
    __tablename__ = "mitre_tactics"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # e.g. TA0001
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class MitreTechnique(Base, TimestampMixin):
    """MITRE ATT&CK Technique definition matching frontend MitreTechnique."""
    __tablename__ = "mitre_techniques"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # e.g. T1190
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactics: Mapped[List[str]] = mapped_column(ARRAY(String), default=list, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str] = mapped_column(String(512), nullable=False)


class ThreatMitreMapping(Base, TimestampMixin):
    """Maps threats/incidents to MITRE ATT&CK techniques with verified evidence."""
    __tablename__ = "threat_mitre_mappings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    threat_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("threats.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    technique_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("mitre_techniques.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    confidence: Mapped[int] = mapped_column(Integer, default=80, nullable=False)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


Index("idx_threat_mitre_unique", ThreatMitreMapping.threat_id, ThreatMitreMapping.technique_id, unique=True)
