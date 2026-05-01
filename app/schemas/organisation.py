import uuid
from datetime import datetime
from pydantic import BaseModel, Field, field_validator
from typing import Optional


class OrgRegisterRequest(BaseModel):
    """Schema for organisation registration"""
    name: str = Field(..., min_length=1, max_length=255)
    siret: str = Field(..., pattern=r"^\d{14}$", description="French SIRET number")
    email: str = Field(..., description="Organisation email")
    website: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None, max_length=2048)
    country: Optional[str] = Field(None, max_length=100)
    
    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("Invalid email format")
        return v


class OrgRead(BaseModel):
    """Schema for organisation read/response"""
    id: uuid.UUID
    name: str
    siret: str
    email: str
    website: Optional[str]
    description: Optional[str]
    country: Optional[str]
    trust_score: int
    status: str
    created_at: datetime
    api_key_created_at: Optional[datetime] = None
    api_key_last_used_at: Optional[datetime] = None
    api_key_expires_at: Optional[datetime] = None
    api_key_version: int

    model_config = {"from_attributes": True}
