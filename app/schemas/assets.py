import uuid
from datetime import datetime

from pydantic import BaseModel


class MalwareSampleRead(BaseModel):
    id: uuid.UUID
    name: str
    family: str
    description: str
    hash_md5: str
    hash_sha256: str
    capabilities: list[str] | None
    org_id: uuid.UUID
    tlp: str
    status: str
    submitted_at: datetime | None

    model_config = {"from_attributes": True}


class ThreatActorRead(BaseModel):
    id: uuid.UUID
    name: str
    aliases: list[str] | None
    motivation: str
    country: str | None
    description: str
    org_id: uuid.UUID
    tlp: str
    status: str
    submitted_at: datetime | None

    model_config = {"from_attributes": True}


class ContributorUserRead(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID
    email: str
    must_change_password: bool
    is_active: bool | None
    created_at: datetime | None

    model_config = {"from_attributes": True}
