"""add_organisation_fields_and_nullable_apikeys

Revision ID: c3f1a2b4d5e6
Revises: b9a2f1c4d8e7
Create Date: 2026-05-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c3f1a2b4d5e6"
down_revision: Union[str, Sequence[str], None] = "b9a2f1c4d8e7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "organisations",
        sa.Column("website", sa.String(length=255), nullable=True),
    )
    op.add_column(
        "organisations",
        sa.Column("description", sa.String(length=2048), nullable=True),
    )
    op.add_column(
        "organisations",
        sa.Column("country", sa.String(length=100), nullable=True),
    )
    op.add_column(
        "organisations",
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
    )

    # Make existing API key columns nullable to match model changes
    op.alter_column(
        "organisations",
        "api_key_hash",
        existing_type=sa.String(length=128),
        nullable=True,
    )
    op.alter_column(
        "organisations",
        "api_key_salt",
        existing_type=sa.String(length=32),
        nullable=True,
    )


def downgrade() -> None:
    # Revert API key columns to non-nullable
    op.alter_column(
        "organisations",
        "api_key_salt",
        existing_type=sa.String(length=32),
        nullable=False,
    )
    op.alter_column(
        "organisations",
        "api_key_hash",
        existing_type=sa.String(length=128),
        nullable=False,
    )

    op.drop_column("organisations", "created_at")
    op.drop_column("organisations", "country")
    op.drop_column("organisations", "description")
    op.drop_column("organisations", "website")
