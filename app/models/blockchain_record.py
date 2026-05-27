import uuid
import enum
from datetime import datetime
from sqlalchemy import String, BigInteger, ForeignKey, DateTime, Enum, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class BlockchainEventType(str, enum.Enum):
    IOC_APPROVED = "IOC_APPROVED"
    IOC_FALSE_POSITIVE = "IOC_FALSE_POSITIVE"


class BlockchainRecord(Base):
    __tablename__ = "blockchain_records"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ioc_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("iocs.id"))
    event_type: Mapped[BlockchainEventType] = mapped_column(Enum(BlockchainEventType), nullable=False)
    tx_hash: Mapped[str] = mapped_column(String(66))
    block_number: Mapped[int] = mapped_column(BigInteger)
    chain_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    contract_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    block_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    log_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow)

    ioc: Mapped["IOC"] = relationship("IOC", back_populates="blockchain_records")
