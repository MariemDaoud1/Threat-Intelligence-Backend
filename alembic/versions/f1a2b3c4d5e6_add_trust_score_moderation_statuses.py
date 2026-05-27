"""add trust score moderation statuses

Revision ID: f1a2b3c4d5e6
Revises: e5b1c9f7a2d0
Create Date: 2026-05-26 12:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f1a2b3c4d5e6"
down_revision: Union[str, Sequence[str], None] = "e5b1c9f7a2d0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "organisations",
        "trust_score",
        existing_type=sa.SmallInteger(),
        server_default=sa.text("30"),
    )

    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE iocstatus ADD VALUE IF NOT EXISTS 'APPROVED';")
        op.execute("ALTER TYPE malwarestatus ADD VALUE IF NOT EXISTS 'approved';")
        op.execute("ALTER TYPE threatactorstatus ADD VALUE IF NOT EXISTS 'approved';")

    op.execute("UPDATE iocs SET status = 'APPROVED' WHERE status::text IN ('VALIDATED', 'validated');")
    op.execute("UPDATE malware_samples SET status = 'approved' WHERE status::text = 'validated';")
    op.execute("UPDATE threat_actors SET status = 'approved' WHERE status::text = 'validated';")

    op.alter_column(
        "malware_samples",
        "status",
        existing_type=sa.Enum(name="malwarestatus"),
        server_default=sa.text("'pending'::malwarestatus"),
    )
    op.alter_column(
        "threat_actors",
        "status",
        existing_type=sa.Enum(name="threatactorstatus"),
        server_default=sa.text("'pending'::threatactorstatus"),
    )


def downgrade() -> None:
    op.execute("UPDATE iocs SET status = 'VALIDATED' WHERE status::text = 'APPROVED';")
    op.execute("UPDATE malware_samples SET status = 'validated' WHERE status::text = 'approved';")
    op.execute("UPDATE threat_actors SET status = 'validated' WHERE status::text = 'approved';")

    op.alter_column(
        "organisations",
        "trust_score",
        existing_type=sa.SmallInteger(),
        server_default=sa.text("0"),
    )
    op.alter_column(
        "malware_samples",
        "status",
        existing_type=sa.Enum(name="malwarestatus"),
        server_default=sa.text("'validated'::malwarestatus"),
    )
    op.alter_column(
        "threat_actors",
        "status",
        existing_type=sa.Enum(name="threatactorstatus"),
        server_default=sa.text("'validated'::threatactorstatus"),
    )
