"""add llm_analysis table

Revision ID: 009_add_llm_analysis_table
Revises: 008_investigation_subsystem
Create Date: 2026-09-15 10:35:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "009_add_llm_analysis_table"
down_revision: Union[str, None] = "008_investigation_subsystem"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    try:
        op.create_table(
            "llm_analysis",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("threat_id", sa.String(64), sa.ForeignKey("threats.id", ondelete="CASCADE"), nullable=False),
            sa.Column("model", sa.String(128), nullable=False),
            sa.Column("prompt_version", sa.String(64), nullable=False),
            sa.Column("generated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("output", postgresql.JSONB(), nullable=False),
            sa.Column("confidence", sa.Float(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
        op.create_index("idx_llm_analysis_threat_id", "llm_analysis", ["threat_id"])
        op.create_index("idx_llm_analysis_generated_at", "llm_analysis", ["generated_at"])
    except Exception:
        pass


def downgrade() -> None:
    try:
        op.drop_index("idx_llm_analysis_generated_at", "llm_analysis")
        op.drop_index("idx_llm_analysis_threat_id", "llm_analysis")
        op.drop_table("llm_analysis")
    except Exception:
        pass
