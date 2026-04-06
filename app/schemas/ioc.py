import re
import uuid
from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime
from app.models.ioc import IOCType, IOCStatus

#client sends a new IOC to the API
class IOCCreate(BaseModel):
    type: IOCType
    value: str = Field(..., min_length=1, max_length=1000)
    description: Optional[str] = Field(None, max_length=2048)

    @field_validator("value")
    @classmethod
    def validate_ioc_value(cls, v, info):
        patterns = {
           IOCType.IP:   r"^\d{1,3}(\.\d{1,3}){3}$",
            IOCType.URL:  r"^https?://\S+$",
            IOCType.HASH: r"^[a-fA-F0-9]{32,64}$",
            IOCType.EMAIL: r"^[^@]+@[^@]+\.[^@]+$",
        }
        ioc_type = info.data.get("type")
        if ioc_type and not re.match(patterns[ioc_type], v):
            raise ValueError(f"Value does not match expected pattern for type {ioc_type}")
        return v
    
#API returns IOC data to the client
class IOCRead(BaseModel):
    id: uuid.UUID
    type: IOCType
    value: str
    description: Optional[str]
    org_id: uuid.UUID
    danger_score: Optional[int]
    threat_category: Optional[str]
    status: IOCStatus
    submitted_at: Optional[datetime]

    model_config = {"from_attributes": True}   # permet de convertir un modèle SQLAlchemy en JSON