"""mitre attack integration columns

Revision ID: 007_mitre_attack_integration
Revises: 006_threat_scoring_factors
Create Date: 2026-09-14 22:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "007_mitre_attack_integration"
down_revision: Union[str, None] = "006_threat_scoring_factors"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    try:
        op.add_column("mitre_techniques", sa.Column("is_subtechnique", sa.Boolean(), server_default="false", nullable=False))
        op.add_column("mitre_techniques", sa.Column("parent_technique_id", sa.String(32), nullable=True))
    except Exception:
        pass

    try:
        op.add_column("threat_mitre_mappings", sa.Column("technique_name", sa.String(255), server_default="Technique", nullable=False))
        op.add_column("threat_mitre_mappings", sa.Column("tactic", sa.String(128), server_default="Execution", nullable=False))
        op.add_column("threat_mitre_mappings", sa.Column("source", sa.String(128), server_default="behavioral_sensor", nullable=False))
    except Exception:
        pass


def downgrade() -> None:
    op.drop_column("threat_mitre_mappings", "source")
    op.drop_column("threat_mitre_mappings", "tactic")
    op.drop_column("threat_mitre_mappings", "technique_name")
    op.drop_column("mitre_techniques", "parent_technique_id")
    op.drop_column("mitre_techniques", "is_subtechnique")
