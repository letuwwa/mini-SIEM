"""constrain usernames

Revision ID: 7c91e2b4a6d8
Revises: 1f4d7b3a9c2e
Create Date: 2026-08-26 00:00:00.000000

"""

from collections.abc import Sequence

from alembic import op

revision: str = "7c91e2b4a6d8"
down_revision: str | Sequence[str] | None = "1f4d7b3a9c2e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_check_constraint(
        "ck_users_username_no_at",
        "users",
        "username NOT LIKE '%@%'",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_users_username_no_at",
        "users",
        type_="check",
    )
