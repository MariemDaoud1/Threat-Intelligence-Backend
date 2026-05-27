import re
import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from app.models.ioc import IOCStatus, IOCType


class IOCCreate(BaseModel):
    type: IOCType
    value: str = Field(..., min_length=1, max_length=1000)
    description: Optional[str] = Field(None, max_length=2048)
    tlp: str = Field(default="green", max_length=20)
    confidence: int = Field(default=0, ge=0, le=100)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: list[str] = Field(default_factory=list)
    source_context: Optional[str] = Field(None, max_length=2048)

    @field_validator("value")
    @classmethod
    def validate_ioc_value(cls, v, info):
        patterns = {
            IOCType.IP: r"^\d{1,3}(\.\d{1,3}){3}$",
            IOCType.URL: r"^https?://\S+$",
            IOCType.HASH: r"^[a-fA-F0-9]{32,64}$",
            IOCType.EMAIL: r"^[^@]+@[^@]+\.[^@]+$",
        }
        ioc_type = info.data.get("type")
        if ioc_type and not re.match(patterns[ioc_type], v):
            raise ValueError(f"Value does not match expected pattern for type {ioc_type}")
        return v


class IOCRead(BaseModel):
    id: uuid.UUID
    type: IOCType
    value: str
    description: Optional[str]
    org_id: uuid.UUID
    tlp: str
    confidence: int
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    tags: list[str] | None
    source_context: Optional[str]
    danger_score: Optional[int]
    threat_category: Optional[str]
    status: IOCStatus
    submitted_at: Optional[datetime]

    model_config = {"from_attributes": True}
