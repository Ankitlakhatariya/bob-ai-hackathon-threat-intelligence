"""initial schema

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-09-14 21:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("supabase_id", sa.String(128), unique=True, nullable=False),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column("role", sa.String(32), server_default="ANALYST", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_users_supabase_id", "users", ["supabase_id"])
    op.create_index("idx_users_email", "users", ["email"])

    # 2. threats
    op.create_table(
        "threats",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(32), server_default="medium", nullable=False),
        sa.Column("status", sa.String(32), server_default="active", nullable=False),
        sa.Column("confidence", sa.Integer(), server_default="70", nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at_custom", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("alert_ids", postgresql.ARRAY(sa.String()), server_default="{}", nullable=False),
        sa.Column("mitre_techniques", postgresql.ARRAY(sa.String()), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_threats_status_severity", "threats", ["status", "severity"])

    # 3. alerts
    op.create_table(
        "alerts",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("team_id", sa.String(64), server_default="t-soc-north", nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("source_label", sa.String(128), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), server_default="open", nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("related_threat_id", sa.String(64), sa.ForeignKey("threats.id", ondelete="SET NULL"), nullable=True),
        sa.Column("mitre_techniques", postgresql.ARRAY(sa.String()), server_default="{}", nullable=False),
        sa.Column("indicators", postgresql.ARRAY(sa.String()), server_default="{}", nullable=False),
        sa.Column("raw_data", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_alerts_status_severity", "alerts", ["status", "severity"])
    op.create_index("idx_alerts_source_timestamp", "alerts", ["source", "timestamp"])

    # 4. events
    op.create_table(
        "events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("alert_id", sa.String(64), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=True),
        sa.Column("event_id", sa.String(128), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
        sa.Column("source_type", sa.String(64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("destination_ip", sa.String(45), nullable=True),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(32), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("username", sa.String(255), nullable=True),
        sa.Column("domain", sa.String(255), nullable=True),
        sa.Column("file_hash", sa.String(128), nullable=True),
        sa.Column("process_name", sa.String(255), nullable=True),
        sa.Column("command_line", sa.Text(), nullable=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("indicators", postgresql.ARRAY(sa.String()), server_default="{}", nullable=False),
        sa.Column("metadata_info", postgresql.JSONB(), nullable=True),
        sa.Column("raw_data", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # 5. correlations
    op.create_table(
        "correlations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("alert_id", sa.String(64), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("related_alert_id", sa.String(64), sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("threat_id", sa.String(64), sa.ForeignKey("threats.id", ondelete="SET NULL"), nullable=True),
        sa.Column("correlation_reason", sa.Text(), nullable=False),
        sa.Column("correlation_score", sa.Float(), nullable=False),
        sa.Column("rule_name", sa.String(128), server_default="deterministic_rule", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # 6. indicators
    op.create_table(
        "indicators",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("indicator_value", sa.String(512), unique=True, nullable=False),
        sa.Column("indicator_type", sa.String(32), nullable=False),
        sa.Column("threat_type", sa.String(128), server_default="generic_threat", nullable=False),
        sa.Column("confidence", sa.Integer(), server_default="80", nullable=False),
        sa.Column("reputation", sa.String(32), server_default="suspicious", nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("source", sa.String(128), server_default="internal_enrichment", nullable=False),
        sa.Column("tags", postgresql.ARRAY(sa.String()), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # 7. investigations
    op.create_table(
        "investigations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("threat_id", sa.String(64), sa.ForeignKey("threats.id", ondelete="SET NULL"), nullable=True),
        sa.Column("alert_id", sa.String(64), sa.ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("status", sa.String(32), server_default="open", nullable=False),
        sa.Column("priority", sa.String(16), server_default="P2", nullable=False),
        sa.Column("assigned_to", sa.String(255), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("findings", sa.Text(), nullable=True),
        sa.Column("resolution_summary", sa.Text(), nullable=True),
        sa.Column("timeline_events", postgresql.JSONB(), server_default="[]", nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # 8. mitre_tactics
    op.create_table(
        "mitre_tactics",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # 9. mitre_techniques
    op.create_table(
        "mitre_techniques",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("tactics", postgresql.ARRAY(sa.String()), server_default="{}", nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("url", sa.String(512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # 10. threat_mitre_mappings
    op.create_table(
        "threat_mitre_mappings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("threat_id", sa.String(64), sa.ForeignKey("threats.id", ondelete="CASCADE"), nullable=False),
        sa.Column("technique_id", sa.String(32), sa.ForeignKey("mitre_techniques.id", ondelete="CASCADE"), nullable=False),
        sa.Column("confidence", sa.Integer(), server_default="80", nullable=False),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # 11. bluf_reports
    op.create_table(
        "bluf_reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("threat_id", sa.String(64), sa.ForeignKey("threats.id", ondelete="CASCADE"), unique=True, nullable=False),
        sa.Column("bottom_line", sa.Text(), nullable=False),
        sa.Column("impact", sa.Text(), nullable=False),
        sa.Column("key_evidence", postgresql.ARRAY(sa.String()), server_default="{}", nullable=False),
        sa.Column("recommended_focus", sa.Text(), nullable=False),
        sa.Column("generated_by", sa.String(128), server_default="ThreatLens Correlation Engine", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # 12. data_sources
    op.create_table(
        "data_sources",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("source_type", sa.String(64), server_default="sensor", nullable=False),
        sa.Column("detail", sa.String(255), nullable=False),
        sa.Column("health", sa.String(32), server_default="healthy", nullable=False),
        sa.Column("lag_seconds", sa.Integer(), server_default="0", nullable=True),
        sa.Column("last_heartbeat", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # 13. audit_logs
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", sa.String(128), nullable=True),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("entity_type", sa.String(64), nullable=False),
        sa.Column("entity_id", sa.String(128), nullable=True),
        sa.Column("details", postgresql.JSONB(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("data_sources")
    op.drop_table("bluf_reports")
    op.drop_table("threat_mitre_mappings")
    op.drop_table("mitre_techniques")
    op.drop_table("mitre_tactics")
    op.drop_table("investigations")
    op.drop_table("indicators")
    op.drop_table("correlations")
    op.drop_table("events")
    op.drop_table("alerts")
    op.drop_table("threats")
    op.drop_table("users")
