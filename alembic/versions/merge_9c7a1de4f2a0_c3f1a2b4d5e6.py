"""merge heads 9c7a1de4f2a0 and c3f1a2b4d5e6

Revision ID: merge_9c7a1de4f2a0_c3f1a2b4d5e6
Revises: 9c7a1de4f2a0, c3f1a2b4d5e6
Create Date: 2026-05-01 11:10:00.000000

This is a no-op merge revision to unify multiple heads in the Alembic history.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "merge_9c7a1de4f2a0_c3f1a2b4d5e6"
down_revision: Union[str, Sequence[str], None] = ("9c7a1de4f2a0", "c3f1a2b4d5e6")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Intentionally empty: this revision merges two independent heads.
    pass


def downgrade() -> None:
    # Downgrade of a merge revision is a no-op.
    pass
