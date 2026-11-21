"""001 initial schema

Revision ID: 001
Revises:
Create Date: 2024-11-01
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email_hmac", sa.String(64), nullable=False, index=True),
        sa.Column("state", sa.String(32), nullable=False, server_default="pending_verification"),
        sa.Column("consent_version", sa.String(16), nullable=False),
        sa.Column("consented_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modules_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("modules_done", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("modules_failed", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_scans_email_hmac_created", "scans", ["email_hmac", "created_at"])
    op.create_index("ix_scans_expires_at", "scans", ["expires_at"])

    op.create_table(
        "verification_challenges",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("code_hash", sa.String(64), nullable=False),
        sa.Column("magic_token_hash", sa.String(64), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "scan_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True, index=True),
        sa.Column("payload_enc", sa.LargeBinary(), nullable=False),
        sa.Column("key_id", sa.String(64), nullable=False, server_default="v1"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "abuse_counters",
        sa.Column("key_hmac", sa.String(64), primary_key=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index("ix_abuse_window", "abuse_counters", ["key_hmac", "window_start"])

    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("event", sa.String(50), nullable=False),
        sa.Column("meta", postgresql.JSONB(), nullable=True),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("abuse_counters")
    op.drop_table("scan_results")
    op.drop_table("verification_challenges")
    op.drop_table("scans")
