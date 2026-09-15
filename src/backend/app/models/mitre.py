import uuid
from typing import List, Optional
from sqlalchemy import String, Text, Integer, Boolean, ForeignKey, Index, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.database import Base, TimestampMixin, StringArrayType


class MitreTactic(Base, TimestampMixin):
    """MITRE ATT&CK Tactic definition."""
    __tablename__ = "mitre_tactics"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # e.g. TA0001
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class MitreTechnique(Base, TimestampMixin):
    """MITRE ATT&CK Technique and Sub-technique definition."""
    __tablename__ = "mitre_techniques"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # e.g. T1190 or T1059.001
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactics: Mapped[List[str]] = mapped_column(StringArrayType(), default=list, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    url: Mapped[str] = mapped_column(String(512), nullable=False)
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    parent_technique_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)


class ThreatMitreMapping(Base, TimestampMixin):
    """Maps threats/incidents to MITRE ATT&CK techniques with verified behavioral evidence."""
    __tablename__ = "threat_mitre_mappings"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
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
    technique_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic: Mapped[str] = mapped_column(String(128), nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=80, nullable=False)  # 0-100
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(128), default="behavioral_sensor", nullable=False)


Index("idx_threat_mitre_unique", ThreatMitreMapping.threat_id, ThreatMitreMapping.technique_id, unique=True)
Index("idx_threat_mitre_tactic", ThreatMitreMapping.tactic)
