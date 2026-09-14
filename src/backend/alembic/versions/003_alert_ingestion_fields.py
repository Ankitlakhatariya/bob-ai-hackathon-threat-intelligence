"""alert ingestion fields and indexes

Revision ID: 003_alert_ingestion_fields
Revises: 002_add_user_hashed_password
Create Date: 2026-09-14 21:50:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "003_alert_ingestion_fields"
down_revision: Union[str, None] = "002_add_user_hashed_password"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    try:
        op.add_column("alerts", sa.Column("event_type", sa.String(128), nullable=True))
        op.add_column("alerts", sa.Column("source_ip", sa.String(45), nullable=True))
        op.add_column("alerts", sa.Column("destination_ip", sa.String(45), nullable=True))
        op.add_column("alerts", sa.Column("hostname", sa.String(255), nullable=True))
        op.add_column("alerts", sa.Column("username", sa.String(255), nullable=True))
        op.add_column("alerts", sa.Column("metadata_info", postgresql.JSONB(), nullable=True))

        op.create_index("idx_alerts_event_type", "alerts", ["event_type"])
        op.create_index("idx_alerts_ip_lookup", "alerts", ["source_ip", "destination_ip"])
        op.create_index("idx_alerts_host_user", "alerts", ["hostname", "username"])
    except Exception:
        pass


def downgrade() -> None:
    op.drop_index("idx_alerts_host_user", "alerts")
    op.drop_index("idx_alerts_ip_lookup", "alerts")
    op.drop_index("idx_alerts_event_type", "alerts")
    op.drop_column("alerts", "metadata_info")
    op.drop_column("alerts", "username")
    op.drop_column("alerts", "hostname")
    op.drop_column("alerts", "destination_ip")
    op.drop_column("alerts", "source_ip")
    op.drop_column("alerts", "event_type")
