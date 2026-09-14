"""threat scoring factors column

Revision ID: 006_threat_scoring_factors
Revises: 005_threat_correlation_fields
Create Date: 2026-09-14 22:20:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "006_threat_scoring_factors"
down_revision: Union[str, None] = "005_threat_correlation_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    try:
        op.add_column("threats", sa.Column("scoring_factors", postgresql.JSONB(), nullable=True))
    except Exception:
        pass


def downgrade() -> None:
    op.drop_column("threats", "scoring_factors")
