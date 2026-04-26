"""add_api_key_lifecycle_fields

Revision ID: b9a2f1c4d8e7
Revises: dc5689c2bf86
Create Date: 2026-04-11 19:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "b9a2f1c4d8e7"
down_revision: Union[str, Sequence[str], None] = "dc5689c2bf86"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("organisations", sa.Column("api_key_created_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("organisations", sa.Column("api_key_last_used_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("organisations", sa.Column("api_key_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("organisations", sa.Column("api_key_revoked_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("organisations", sa.Column("api_key_version", sa.SmallInteger(), nullable=False, server_default="1"))


def downgrade() -> None:
    op.drop_column("organisations", "api_key_version")
    op.drop_column("organisations", "api_key_revoked_at")
    op.drop_column("organisations", "api_key_expires_at")
    op.drop_column("organisations", "api_key_last_used_at")
    op.drop_column("organisations", "api_key_created_at")
