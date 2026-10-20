"""index token blocklist expiry

Revision ID: 1f4d7b3a9c2e
Revises: 8489b5758f6b
Create Date: 2026-08-26 00:00:00.000000

"""

from collections.abc import Sequence

from alembic import op

revision: str = "1f4d7b3a9c2e"
down_revision: str | Sequence[str] | None = "8489b5758f6b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        op.f("ix_token_blocklist_expires_at"),
        "token_blocklist",
        ["expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_token_blocklist_expires_at"),
        table_name="token_blocklist",
    )
