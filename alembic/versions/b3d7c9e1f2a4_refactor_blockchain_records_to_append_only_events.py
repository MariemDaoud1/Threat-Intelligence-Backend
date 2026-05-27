"""refactor blockchain_records to append-only events

Revision ID: b3d7c9e1f2a4
Revises: f1a2b3c4d5e6
Create Date: 2026-05-26 16:30:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b3d7c9e1f2a4"
down_revision: Union[str, Sequence[str], None] = "f1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


blockchain_event_type = sa.Enum("IOC_APPROVED", "IOC_FALSE_POSITIVE", name="blockchaineventtype")


def upgrade() -> None:
    bind = op.get_bind()
    blockchain_event_type.create(bind, checkfirst=True)

    op.add_column("blockchain_records", sa.Column("event_type", blockchain_event_type, nullable=True))
    op.add_column("blockchain_records", sa.Column("chain_id", sa.Integer(), nullable=True))
    op.add_column("blockchain_records", sa.Column("contract_address", sa.String(length=42), nullable=True))
    op.add_column("blockchain_records", sa.Column("block_hash", sa.String(length=66), nullable=True))
    op.add_column("blockchain_records", sa.Column("log_index", sa.Integer(), nullable=True))

    op.execute("UPDATE blockchain_records SET event_type = 'IOC_APPROVED' WHERE event_type IS NULL;")

    op.alter_column("blockchain_records", "event_type", existing_type=blockchain_event_type, nullable=False)

    # Drop one-to-one unique constraint on ioc_id safely without assuming the exact name.
    op.execute(
        """
DO $$
DECLARE
    target_constraint text;
BEGIN
    SELECT c.conname
    INTO target_constraint
    FROM pg_constraint c
    JOIN pg_class t ON t.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = current_schema()
      AND t.relname = 'blockchain_records'
      AND c.contype = 'u'
      AND c.conkey = ARRAY[
        (
            SELECT a.attnum
            FROM pg_attribute a
            WHERE a.attrelid = t.oid
              AND a.attname = 'ioc_id'
              AND NOT a.attisdropped
            LIMIT 1
        )
      ]::smallint[]
    LIMIT 1;

    IF target_constraint IS NOT NULL THEN
        EXECUTE format(
            'ALTER TABLE %I.%I DROP CONSTRAINT %I',
            current_schema(),
            'blockchain_records',
            target_constraint
        );
    END IF;
END
$$;
        """
    )

    op.execute("CREATE INDEX IF NOT EXISTS ix_blockchain_records_ioc_id ON blockchain_records (ioc_id);")
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_blockchain_records_ioc_id_recorded_at_desc "
        "ON blockchain_records (ioc_id, recorded_at DESC);"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_blockchain_records_ioc_id_recorded_at_desc;")
    op.execute("DROP INDEX IF EXISTS ix_blockchain_records_ioc_id;")

    # Downgrade back to one-row-per-IOC only if data is compatible.
    op.execute(
        """
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM blockchain_records
        GROUP BY ioc_id
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'Cannot downgrade: blockchain_records contains multiple rows per ioc_id';
    END IF;
END
$$;
        """
    )
    op.execute(
        "ALTER TABLE blockchain_records "
        "ADD CONSTRAINT blockchain_records_ioc_id_key UNIQUE (ioc_id);"
    )

    op.drop_column("blockchain_records", "log_index")
    op.drop_column("blockchain_records", "block_hash")
    op.drop_column("blockchain_records", "contract_address")
    op.drop_column("blockchain_records", "chain_id")
    op.drop_column("blockchain_records", "event_type")

    bind = op.get_bind()
    blockchain_event_type.drop(bind, checkfirst=True)
