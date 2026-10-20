"""Add security events.

Revision ID: 2b8c4d6e9f10
Revises: 7c91e2b4a6d8
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "2b8c4d6e9f10"
down_revision = "7c91e2b4a6d8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.String(255), nullable=False),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "severity",
            sa.String(8),
            nullable=False,
        ),
        sa.Column("actor_user_id", sa.String(255), nullable=True),
        sa.Column("actor_ip", sa.String(45), nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="ck_security_events_severity",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source", "event_id", name="uq_security_events_source_event_id"
        ),
    )
    op.create_index(
        "ix_security_events_occurred_at", "security_events", ["occurred_at"]
    )
    op.create_index(
        "ix_security_events_source_time", "security_events", ["source", "occurred_at"]
    )
    op.create_index(
        "ix_security_events_type_time", "security_events", ["event_type", "occurred_at"]
    )
    op.create_index(
        "ix_security_events_source_actor_time",
        "security_events",
        ["source", "actor_user_id", "occurred_at"],
    )


def downgrade() -> None:
    op.drop_table("security_events")
