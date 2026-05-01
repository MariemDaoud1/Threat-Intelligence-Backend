"""add iocstatus validated value

Revision ID: d4f6e2a1b3c4
Revises: merge_9c7a1de4f2a0_c3f1a2b4d5e6
Create Date: 2026-05-01 11:14:00.000000

Adds the missing 'VALIDATED' label to the Postgres `iocstatus` enum
and normalizes any existing rows that used the malformed 'VALIDaTED'.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "d4f6e2a1b3c4"
down_revision: Union[str, Sequence[str], None] = "merge_9c7a1de4f2a0_c3f1a2b4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add the VALIDATED enum value if it doesn't already exist in a
    # separate autocommit block (Postgres requires new enum values to be
    # visible/committed before they can be used), then normalize rows.
    with op.get_context().autocommit_block():
        op.execute(
            """
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_enum
        WHERE enumtypid = 'iocstatus'::regtype
        AND enumlabel = 'VALIDATED'
    ) THEN
        ALTER TYPE iocstatus ADD VALUE 'VALIDATED';
    END IF;
END
$$;
"""
        )

    # Now that the new value is committed, normalize malformed rows.
    op.execute(
        "UPDATE iocs SET status = 'VALIDATED' WHERE status = 'VALIDaTED';"
    )


def downgrade() -> None:
    # Removing enum values is non-trivial in Postgres and not needed for
    # this project; leave as a no-op to avoid data loss.
    pass
