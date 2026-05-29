import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_db
from app.models.blockchain_record import BlockchainEventType, BlockchainRecord
from app.models.ioc import IOC
from app.schemas.blockchain import BlockchainHistoryRecord, BlockchainVerificationSummary
from app.services.blockchain_service import BlockchainService


router = APIRouter(prefix="/blockchain", tags=["Blockchain"])


def _build_etherscan_tx_url(tx_hash: str, chain_id: int | None) -> str | None:
    # IOC blockchain writes currently target Sepolia.
    if not tx_hash:
        return None
    if chain_id in (None, 11155111):
        return f"https://sepolia.etherscan.io/tx/{tx_hash}"
    return None


async def _get_ioc_or_404(db: AsyncSession, ioc_id: uuid.UUID) -> IOC:
    ioc = await db.get(IOC, ioc_id)
    if ioc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")
    return ioc


@router.get("/verify/{ioc_id}", response_model=BlockchainVerificationSummary)
async def verify_ioc_blockchain(ioc_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    ioc = await _get_ioc_or_404(db, ioc_id)
    rows = (
        await db.execute(
            select(BlockchainRecord)
            .where(BlockchainRecord.ioc_id == ioc_id)
            .order_by(BlockchainRecord.recorded_at.desc(), BlockchainRecord.id.desc())
        )
    ).scalars().all()

    content_hash_hex = "0x" + BlockchainService.compute_ioc_content_hash_bytes32(ioc).hex()
    if not rows:
        return BlockchainVerificationSummary(
            verified=False,
            current_status="no_blockchain_record",
            latest_tx_hash=None,
            block_number=None,
            chain_id=None,
            contract_address=None,
            etherscan_url=None,
            latest_recorded_at=None,
            latest_event_type=None,
            content_hash=content_hash_hex,
            history_length=0,
            is_valid=False,
        )

    latest = rows[0]
    event_value = latest.event_type.value if hasattr(latest.event_type, "value") else str(latest.event_type)
    current_status = "false_positive" if latest.event_type == BlockchainEventType.IOC_FALSE_POSITIVE else "approved"
    return BlockchainVerificationSummary(
        verified=True,
        current_status=current_status,
        latest_tx_hash=latest.tx_hash,
        block_number=latest.block_number,
        chain_id=latest.chain_id,
        contract_address=latest.contract_address,
        etherscan_url=_build_etherscan_tx_url(latest.tx_hash, latest.chain_id),
        latest_recorded_at=latest.recorded_at,
        latest_event_type=event_value,
        content_hash=content_hash_hex,
        history_length=len(rows),
        is_valid=True,
    )


@router.get("/records/{ioc_id}", response_model=list[BlockchainHistoryRecord])
async def list_ioc_blockchain_records(ioc_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    await _get_ioc_or_404(db, ioc_id)
    rows = (
        await db.execute(
            select(BlockchainRecord)
            .where(BlockchainRecord.ioc_id == ioc_id)
            .order_by(BlockchainRecord.recorded_at.asc(), BlockchainRecord.id.asc())
        )
    ).scalars().all()

    return [
        BlockchainHistoryRecord(
            tx_hash=row.tx_hash,
            block_number=row.block_number,
            event_type=row.event_type.value if hasattr(row.event_type, "value") else str(row.event_type),
            recorded_at=row.recorded_at,
            etherscan_url=_build_etherscan_tx_url(row.tx_hash, row.chain_id),
        )
        for row in rows
    ]
