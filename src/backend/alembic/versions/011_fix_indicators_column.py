"""fix indicators table - make indicator_value nullable, make indicator not null

Revision ID: 011_fix_indicators_column
Revises: 010_make_supabase_id_nullable
Create Date: 2026-09-15 11:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "011_fix_indicators_column"
down_revision: Union[str, None] = "010_make_supabase_id_nullable"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Step 1: Copy indicator_value into indicator for any rows that have indicator_value
    #         but no indicator yet (handles pre-existing data)
    op.execute(
        "UPDATE indicators SET indicator = indicator_value WHERE indicator IS NULL AND indicator_value IS NOT NULL"
    )

    # Step 2: For any rows still missing indicator, set a placeholder so NOT NULL can be applied
    op.execute(
        "UPDATE indicators SET indicator = 'unknown' WHERE indicator IS NULL"
    )

    # Step 3: Make the new 'indicator' column NOT NULL (now that all rows are populated)
    op.alter_column(
        "indicators",
        "indicator",
        existing_type=sa.String(512),
        nullable=False,
    )

    # Step 4: Make the old 'indicator_value' column nullable (it is now legacy / redundant)
    op.alter_column(
        "indicators",
        "indicator_value",
        existing_type=sa.String(512),
        nullable=True,
    )


def downgrade() -> None:
    op.alter_column("indicators", "indicator_value", existing_type=sa.String(512), nullable=False)
    op.alter_column("indicators", "indicator", existing_type=sa.String(512), nullable=True)
