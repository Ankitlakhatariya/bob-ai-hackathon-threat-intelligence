"""investigation subsystem enhancements

Revision ID: 008_investigation_subsystem
Revises: 007_mitre_attack_integration
Create Date: 2026-09-14 22:55:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "008_investigation_subsystem"
down_revision: Union[str, None] = "007_mitre_attack_integration"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    try:
        op.add_column("investigations", sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True))
    except Exception:
        pass

    try:
        op.create_index("idx_investigations_threat_id", "investigations", ["threat_id"])
    except Exception:
        pass

    try:
        op.create_index("idx_investigations_assigned_to", "investigations", ["assigned_to"])
    except Exception:
        pass


def downgrade() -> None:
    try:
        op.drop_index("idx_investigations_assigned_to", table_name="investigations")
    except Exception:
        pass

    try:
        op.drop_index("idx_investigations_threat_id", table_name="investigations")
    except Exception:
        pass

    try:
        op.drop_column("investigations", "closed_at")
    except Exception:
        pass
