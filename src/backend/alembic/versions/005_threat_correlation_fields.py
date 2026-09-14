"""threat correlation engine fields and indexes

Revision ID: 005_threat_correlation_fields
Revises: 004_threat_intel_model
Create Date: 2026-09-14 22:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "005_threat_correlation_fields"
down_revision: Union[str, None] = "004_threat_intel_model"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    try:
        op.add_column("threats", sa.Column("threat_id", sa.String(64), nullable=True))
        op.add_column("threats", sa.Column("description", sa.Text(), nullable=True))
        op.add_column("threats", sa.Column("risk_score", sa.Integer(), server_default="50", nullable=False))
        op.add_column("threats", sa.Column("alert_count", sa.Integer(), server_default="1", nullable=False))
        op.add_column("threats", sa.Column("affected_assets", postgresql.ARRAY(sa.String()), server_default="{}", nullable=False))
        op.add_column("threats", sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
        op.add_column("threats", sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))

        # Copy existing id into threat_id if null
        op.execute("UPDATE threats SET threat_id = id WHERE threat_id IS NULL")
        op.execute("UPDATE threats SET description = summary WHERE description IS NULL")

        op.create_index("idx_threats_timeline", "threats", ["first_seen", "last_seen"])
        op.create_index("idx_threats_risk_score", "threats", ["risk_score"])
    except Exception:
        pass


def downgrade() -> None:
    op.drop_index("idx_threats_risk_score", "threats")
    op.drop_index("idx_threats_timeline", "threats")
    op.drop_column("threats", "last_seen")
    op.drop_column("threats", "first_seen")
    op.drop_column("threats", "affected_assets")
    op.drop_column("threats", "alert_count")
    op.drop_column("threats", "risk_score")
    op.drop_column("threats", "description")
    op.drop_column("threats", "threat_id")
