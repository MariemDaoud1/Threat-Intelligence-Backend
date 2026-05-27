"""web_portal_alignment_and_admin_role

Revision ID: e5b1c9f7a2d0
Revises: d4f6e2a1b3c4
Create Date: 2026-05-01 18:00:00.000000
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import uuid
from datetime import datetime
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "e5b1c9f7a2d0"
down_revision: Union[str, Sequence[str], None] = "d4f6e2a1b3c4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 390000)
    return f"{salt}${base64.b64encode(digest).decode()}"


def upgrade() -> None:
    op.add_column("contributor_users", sa.Column("role", sa.String(length=20), nullable=True))
    op.execute("UPDATE contributor_users SET role = 'contributor' WHERE role IS NULL;")
    op.alter_column("contributor_users", "role", nullable=False)
    op.alter_column("contributor_users", "org_id", existing_type=sa.UUID(), nullable=True)

    op.add_column("iocs", sa.Column("tlp", sa.String(length=20), nullable=True))
    op.add_column("iocs", sa.Column("confidence", sa.SmallInteger(), nullable=True))
    op.add_column("iocs", sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True))
    op.add_column("iocs", sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True))
    op.add_column("iocs", sa.Column("tags", postgresql.ARRAY(sa.String()), nullable=True))
    op.add_column("iocs", sa.Column("source_context", sa.Text(), nullable=True))
    op.execute("UPDATE iocs SET tlp = 'green' WHERE tlp IS NULL;")
    op.execute("UPDATE iocs SET confidence = 0 WHERE confidence IS NULL;")
    op.alter_column("iocs", "tlp", nullable=False)
    op.alter_column("iocs", "confidence", nullable=False)

    op.alter_column("malware_samples", "hash_md5", existing_type=sa.String(length=32), nullable=True)
    op.alter_column("malware_samples", "hash_sha256", existing_type=sa.String(length=64), nullable=True)
    op.alter_column("threat_actors", "country", existing_type=sa.String(length=10), type_=sa.String(length=100))

    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE iocstatus ADD VALUE IF NOT EXISTS 'REVOKED';")
        op.execute("ALTER TYPE iocstatus ADD VALUE IF NOT EXISTS 'FALSE_POSITIVE';")
        op.execute("ALTER TYPE iocstatus ADD VALUE IF NOT EXISTS 'DEPRECATED';")
        op.execute("ALTER TYPE malwarestatus ADD VALUE IF NOT EXISTS 'false_positive';")
        op.execute("ALTER TYPE threatactorstatus ADD VALUE IF NOT EXISTS 'false_positive';")

    admin_email = os.getenv("ADMIN_LOGIN", "admin")
    admin_password = os.getenv("ADMIN_PASSWORD", "admin123")
    admin_hash = _hash_password(admin_password)
    admin_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    op.execute(
        sa.text(
            """
            INSERT INTO contributor_users (
                id, org_id, email, hashed_password, role, must_change_password, is_active, created_at
            )
            VALUES (
                :id, NULL, :email, :hashed_password, 'admin', FALSE, TRUE, :created_at
            )
            ON CONFLICT (email) DO UPDATE
            SET hashed_password = EXCLUDED.hashed_password,
                role = 'admin',
                must_change_password = FALSE,
                is_active = TRUE,
                org_id = NULL;
            """
        ).bindparams(
            id=admin_id,
            email=admin_email,
            hashed_password=admin_hash,
            created_at=now,
        )
    )


def downgrade() -> None:
    op.drop_column("iocs", "source_context")
    op.drop_column("iocs", "tags")
    op.drop_column("iocs", "last_seen")
    op.drop_column("iocs", "first_seen")
    op.drop_column("iocs", "confidence")
    op.drop_column("iocs", "tlp")

    op.alter_column("threat_actors", "country", existing_type=sa.String(length=100), type_=sa.String(length=10))
    op.alter_column("malware_samples", "hash_sha256", existing_type=sa.String(length=64), nullable=False)
    op.alter_column("malware_samples", "hash_md5", existing_type=sa.String(length=32), nullable=False)

    op.execute("DELETE FROM contributor_users WHERE role = 'admin';")
    op.drop_column("contributor_users", "role")
    op.alter_column("contributor_users", "org_id", existing_type=sa.UUID(), nullable=False)
