import uuid
from datetime import datetime
from sqlalchemy import DateTime, String, SmallInteger, CheckConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from app.db.base import Base

class Organisation(Base):
    __tablename__ = "organisations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid(), default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    siret: Mapped[str] = mapped_column(String(14), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    api_key_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    api_key_salt: Mapped[str] = mapped_column(String(32), nullable=False)
    trust_score: Mapped[int] = mapped_column(
        SmallInteger,
        CheckConstraint('trust_score BETWEEN 0 AND 100', name='check_trust_score_range'), default=0)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    api_key_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    api_key_last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    api_key_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    api_key_revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    api_key_version: Mapped[int] = mapped_column(SmallInteger, default=1)
    iocs: Mapped[list["IOC"]] = relationship("IOC", back_populates="organisation")
    threat_actors = relationship("ThreatActor", back_populates="organisation")
    malware_samples = relationship("MalwareSample", back_populates="organisation")
    contributor_user = relationship("ContributorUser", back_populates="organisation", uselist=False)


# Import required so SQLAlchemy can resolve the "IOC" relationship target at runtime.
from app.models.ioc import IOC  
    