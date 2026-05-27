import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, SmallInteger, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class IOCType(str, enum.Enum):
    IP = "ip"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"


class IOCStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    REVOKED = "revoked"
    FALSE_POSITIVE = "false_positive"
    DEPRECATED = "deprecated"


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type: Mapped[IOCType] = mapped_column(Enum(IOCType), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    org_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("organisations.id"), nullable=False)

    tlp: Mapped[str] = mapped_column(String(20), nullable=False, default="green")
    confidence: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(ARRAY(String), nullable=True)
    source_context: Mapped[str | None] = mapped_column(Text, nullable=True)

    danger_score: Mapped[int | None] = mapped_column(SmallInteger, default=0)
    threat_category: Mapped[str | None] = mapped_column(String(50))
    enrichment_js: Mapped[dict | None] = mapped_column(JSONB)
    ai_feature_importances: Mapped[dict | None] = mapped_column(JSONB)

    status: Mapped[IOCStatus] = mapped_column(Enum(IOCStatus), default=IOCStatus.PENDING)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    organisation: Mapped["Organisation"] = relationship("Organisation", back_populates="iocs")
    blockchain_records: Mapped[list["BlockchainRecord"]] = relationship(
        "BlockchainRecord", back_populates="ioc", order_by="BlockchainRecord.recorded_at.desc()"
    )
