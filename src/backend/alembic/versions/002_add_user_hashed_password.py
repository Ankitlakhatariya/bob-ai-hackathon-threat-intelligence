"""add user hashed_password

Revision ID: 002_add_user_hashed_password
Revises: 001_initial_schema
Create Date: 2026-09-14 21:40:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "002_add_user_hashed_password"
down_revision: Union[str, None] = "001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add hashed_password column to users table if not already present
    try:
        op.add_column("users", sa.Column("hashed_password", sa.String(255), nullable=True))
    except Exception:
        pass


def downgrade() -> None:
    op.drop_column("users", "hashed_password")
