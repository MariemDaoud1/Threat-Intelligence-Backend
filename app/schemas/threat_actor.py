import uuid
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from app.models.threat_actor import Motivation, ThreatActorStatus


class ThreatActorCreate(BaseModel):
    name: str = Field(..., max_length=255)
    aliases: Optional[List[str]] = None
    motivation: Motivation
    country: Optional[str] = Field(None, max_length=100)
    description: str = Field(..., max_length=2048)
    tlp: Optional[str] = Field("green", max_length=20)


class ThreatActorRead(BaseModel):
    id: uuid.UUID
    name: str
    aliases: Optional[List[str]]
    motivation: Motivation
    country: Optional[str]
    description: str
    org_id: uuid.UUID
    tlp: str
    status: ThreatActorStatus
    submitted_at: Optional[datetime]

    model_config = {"from_attributes": True}
