import asyncio
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
import uuid

from app.api.v1.deps import get_db, invalidate_api_key_cache
from app.config import settings
from app.models.organisation import Organisation
from app.rate_limiter import limiter
from app.services.auth_service import AuthService, create_access_token, verify_jwt
from app.services.email_service import EmailService

router = APIRouter(prefix="/admin", tags=["Admin"])


#  Modèle pour le login  
class AdminLogin(BaseModel):
    username: str
    password: str


class ApiKeyStatusResponse(BaseModel):
    org_id: uuid.UUID
    status: str
    api_key_created_at: datetime | None
    api_key_last_used_at: datetime | None
    api_key_expires_at: datetime | None
    api_key_revoked_at: datetime | None
    api_key_version: int


async def _rotate_and_email_api_key(org: Organisation, db: AsyncSession) -> datetime | None:
    raw_key, key_hash, key_salt = AuthService.generate_api_key()
    now = datetime.now(timezone.utc)
    expires_at = None
    if settings.API_KEY_EXPIRE_DAYS > 0:
        expires_at = now + timedelta(days=settings.API_KEY_EXPIRE_DAYS)

    org.api_key_hash = key_hash
    org.api_key_salt = key_salt
    org.api_key_created_at = now
    org.api_key_last_used_at = None
    org.api_key_expires_at = expires_at
    org.api_key_revoked_at = None
    org.api_key_version = (org.api_key_version or 0) + 1

    try:
        await asyncio.to_thread(EmailService.send_api_key_email, org.email, org.name, raw_key)
    except Exception as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Unable to send API key email: {exc}"
        )

    await db.commit()
    await invalidate_api_key_cache()
    raw_key = None
    return expires_at


#  LOGIN  
@router.post("/login")
@limiter.limit("5/minute")
async def admin_login(request: Request, credentials: AdminLogin):
    """Login admin avec body JSON"""
    if credentials.username != "admin" or credentials.password != "admin123":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    token = create_access_token(subject="admin")
    return {"access_token": token, "token_type": "bearer"}

#  AUTRES ROUTES (protégées par JWT)  
@router.get("/requests")
async def list_pending_requests(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_jwt)
):
    try:
        result = await db.execute(select(Organisation).where(Organisation.status == "pending"))
        pending_orgs = result.scalars().all()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable. Check DATABASE_URL and database host."
        )
    data = [
        {
            "id": str(org.id),
            "name": org.name,
            "siret": org.siret,
            "email": org.email,
            "status": org.status,
        }
        for org in pending_orgs
    ]
    return {"data": data, "error": None}


@router.post("/approve/{org_id}")
async def approve_organisation(
    org_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_jwt)
):
    result = await db.execute(select(Organisation).where(Organisation.id == org_id))
    org = result.scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=404, detail="Organisation not found")

    org.status = "approved"
    expires_at = await _rotate_and_email_api_key(org, db)
    return {
        "message": "Organisation approved and API key sent by email",
        "api_key_expires_at": expires_at,
    }


@router.post("/revoke/{org_id}")
async def revoke_organisation(
    org_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_jwt)
):
    result = await db.execute(
        update(Organisation).where(Organisation.id == org_id).values(status="revoked")
    )
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Organisation not found")
    return {"message": "Organisation revoked successfully"}


@router.post("/organisations/{org_id}/api-key/rotate")
async def rotate_organisation_api_key(
    org_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_jwt)
):
    result = await db.execute(select(Organisation).where(Organisation.id == org_id))
    org = result.scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=404, detail="Organisation not found")
    if org.status != "approved":
        raise HTTPException(status_code=400, detail="Organisation must be approved before rotating API key")

    expires_at = await _rotate_and_email_api_key(org, db)
    return {
        "message": "API key rotated and sent by email",
        "api_key_expires_at": expires_at,
    }


@router.post("/organisations/{org_id}/api-key/revoke")
async def revoke_organisation_api_key(
    org_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_jwt)
):
    result = await db.execute(select(Organisation).where(Organisation.id == org_id))
    org = result.scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=404, detail="Organisation not found")

    now = datetime.now(timezone.utc)
    org.api_key_revoked_at = now
    org.api_key_expires_at = now
    await db.commit()
    await invalidate_api_key_cache()
    return {"message": "API key revoked successfully"}


@router.get("/organisations/{org_id}/api-key/status", response_model=ApiKeyStatusResponse)
async def get_organisation_api_key_status(
    org_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_jwt)
):
    result = await db.execute(select(Organisation).where(Organisation.id == org_id))
    org = result.scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=404, detail="Organisation not found")

    return ApiKeyStatusResponse(
        org_id=org.id,
        status=org.status,
        api_key_created_at=org.api_key_created_at,
        api_key_last_used_at=org.api_key_last_used_at,
        api_key_expires_at=org.api_key_expires_at,
        api_key_revoked_at=org.api_key_revoked_at,
        api_key_version=org.api_key_version,
    )