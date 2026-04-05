import uuid
from sqlalchemy import String, SmallInteger, CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from app.db.base import Base

class Organisation(Base):
    __tablename__ = "organisations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    siret: Mapped[str] = mapped_column(String(14), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    api_key_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    api_key_salt: Mapped[str] = mapped_column(String(32), nullable=False)
    trust_score: Mapped[int] = mapped_column(
        SmallInteger,
        CheckConstraint('trust_score BETWEEN 0 AND 100', name='check_trust_score_range'), default=0)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    