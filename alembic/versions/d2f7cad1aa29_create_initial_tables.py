"""create_initial_tables

Revision ID: d2f7cad1aa29
Revises: 
Create Date: 2026-04-05 18:36:49.740736

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd2f7cad1aa29'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Historical revision kept as no-op. The original migration attempted to
    # create indexes before the base tables existed, which breaks clean setup.
    pass
    


def downgrade() -> None:
    """Downgrade schema."""
    pass
