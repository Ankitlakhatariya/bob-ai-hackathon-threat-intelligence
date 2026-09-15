"""make supabase_id nullable on users

Revision ID: 010_make_supabase_id_nullable
Revises: 009_add_llm_analysis_table
Create Date: 2026-09-15 10:55:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "010_make_supabase_id_nullable"
down_revision: Union[str, None] = "009_add_llm_analysis_table"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Make supabase_id nullable — local users (registered via password) don't have a Supabase UUID
    op.alter_column(
        "users",
        "supabase_id",
        existing_type=sa.String(128),
        nullable=True,
    )


def downgrade() -> None:
    # Re-apply NOT NULL (will fail if any rows have NULL supabase_id)
    op.alter_column(
        "users",
        "supabase_id",
        existing_type=sa.String(128),
        nullable=False,
    )
