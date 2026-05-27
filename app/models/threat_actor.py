import enum
import uuid
from datetime import datetime

from sqlalchemy import ARRAY, Column, DateTime, Enum as SAEnum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.base import Base


class Motivation(str, enum.Enum):
    espionage = "espionage"
    financial = "financial"
    hacktivism = "hacktivism"
    sabotage = "sabotage"


class ThreatActorStatus(str, enum.Enum):
    approved = "approved"
    pending = "pending"
    rejected = "rejected"
    false_positive = "false_positive"


class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, unique=True)
    aliases = Column(ARRAY(String), default=[])
    motivation = Column(SAEnum(Motivation), nullable=False)
    country = Column(String(100), nullable=True)
    description = Column(Text, nullable=False)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organisations.id"), nullable=False)
    tlp = Column(String(20), nullable=False, default="green")
    status = Column(SAEnum(ThreatActorStatus), default=ThreatActorStatus.pending)
    submitted_at = Column(DateTime, default=datetime.utcnow)

    organisation = relationship("Organisation", back_populates="threat_actors")
