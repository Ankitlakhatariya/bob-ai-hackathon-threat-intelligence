"""threat intel subsystem columns and indexes

Revision ID: 004_threat_intel_model
Revises: 003_alert_ingestion_fields
Create Date: 2026-09-14 22:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "004_threat_intel_model"
down_revision: Union[str, None] = "003_alert_ingestion_fields"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    try:
        # Check and add columns to indicators
        op.add_column("indicators", sa.Column("indicator", sa.String(512), nullable=True))
        op.add_column("indicators", sa.Column("threat_actor", sa.String(128), nullable=True))
        op.add_column("indicators", sa.Column("campaign", sa.String(128), nullable=True))
        op.add_column("indicators", sa.Column("raw_intelligence", postgresql.JSONB(), nullable=True))

        # Copy existing indicator_value to indicator if present
        op.execute("UPDATE indicators SET indicator = indicator_value WHERE indicator IS NULL AND indicator_value IS NOT NULL")

        op.create_index("idx_indicators_search", "indicators", ["indicator", "indicator_type", "reputation"])
        op.create_index("idx_indicators_actor_campaign", "indicators", ["threat_actor", "campaign"])
    except Exception:
        pass


def downgrade() -> None:
    op.drop_index("idx_indicators_actor_campaign", "indicators")
    op.drop_index("idx_indicators_search", "indicators")
    op.drop_column("indicators", "raw_intelligence")
    op.drop_column("indicators", "campaign")
    op.drop_column("indicators", "threat_actor")
    op.drop_column("indicators", "indicator")
