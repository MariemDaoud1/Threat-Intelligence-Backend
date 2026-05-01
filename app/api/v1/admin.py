import asyncio
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
import uuid

from app.api.v1.deps import get_db, invalidate_api_key_cache
from app.config import settings
from app.models.organisation import Organisation, OrgStatus
from app.models.contributor_user import ContributorUser
from app.models.ioc import IOC, IOCStatus
from app.models.blockchain_record import BlockchainRecord
from app.rate_limiter import limiter
from app.schemas.assets import ContributorUserRead, MalwareSampleRead, ThreatActorRead
from app.services.auth_service import AuthService, create_access_token, verify_jwt
from app.services.asset_service import AssetService
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


class AssetListResponse(BaseModel):
    data: list
    error: None = None


class AssetListMetaResponse(BaseModel):
    page_size: int
    next_cursor: None = None


class AssetCollectionResponse(BaseModel):
    data: list
    meta: AssetListMetaResponse
    error: None = None


async def _rotate_api_key(org: Organisation) -> tuple[str, datetime | None]:
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
    return raw_key, expires_at


async def _send_contributor_access_email(org: Organisation, temporary_password: str) -> None:
    await asyncio.to_thread(
        EmailService.send_contributor_welcome_email,
        org.email,
        org.name,
        temporary_password,
    )


async def _send_rejection_email(org: Organisation, reason: str | None = None) -> None:
    await asyncio.to_thread(
        EmailService.send_rejection_email,
        org.email,
        org.name,
        reason,
    )


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
        result = await db.execute(select(Organisation).where(Organisation.status == OrgStatus.pending))
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
    if org.status == OrgStatus.approved:
        raise HTTPException(status_code=400, detail="Organisation already approved")

    temporary_password = AuthService.generate_temp_password()
    contributor = await db.execute(select(ContributorUser).where(ContributorUser.org_id == org.id))
    existing_contributor = contributor.scalar_one_or_none()
    if existing_contributor is None:
        existing_contributor = ContributorUser(
            org_id=org.id,
            email=org.email,
            hashed_password=AuthService.hash_password(temporary_password),
            must_change_password=True,
            is_active=True,
        )
        db.add(existing_contributor)

    org.status = OrgStatus.approved
    raw_key, expires_at = await _rotate_api_key(org)
    await db.commit()
    await invalidate_api_key_cache()
    try:
        await asyncio.to_thread(EmailService.send_api_key_email, org.email, org.name, raw_key)
        await _send_contributor_access_email(org, temporary_password)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Unable to send contributor welcome email: {exc}",
        )
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
        update(Organisation).where(Organisation.id == org_id).values(status=OrgStatus.revoked)
    )
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Organisation not found")
    return {"message": "Organisation revoked successfully"}


@router.post("/reject/{org_id}")
async def reject_organisation(
    org_id: uuid.UUID,
    reason: str | None = None,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_jwt),
):
    result = await db.execute(select(Organisation).where(Organisation.id == org_id))
    org = result.scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=404, detail="Organisation not found")

    org.status = OrgStatus.revoked
    try:
        await _send_rejection_email(org, reason)
    except Exception as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Unable to send rejection email: {exc}",
        )
    await db.commit()
    return {"message": "Organisation rejected successfully"}


@router.post("/validate-pending/{ioc_id}")
async def validate_pending_ioc(
    ioc_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_jwt),
):
    result = await db.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if ioc is None:
        raise HTTPException(status_code=404, detail="IOC not found")
    if ioc.status != IOCStatus.PENDING:
        raise HTTPException(status_code=400, detail="IOC must be pending before validation")

    ioc.status = IOCStatus.VALIDATED
    ioc.validated_at = datetime.now(timezone.utc)

    tx_hash = f"0x{secrets.token_hex(32)}"
    block_number = int(datetime.now(timezone.utc).timestamp())
    record = await db.execute(select(BlockchainRecord).where(BlockchainRecord.ioc_id == ioc.id))
    existing_record = record.scalar_one_or_none()
    if existing_record is None:
        db.add(BlockchainRecord(ioc_id=ioc.id, tx_hash=tx_hash, block_number=block_number))
    else:
        existing_record.tx_hash = tx_hash
        existing_record.block_number = block_number
        existing_record.recorded_at = datetime.now(timezone.utc)

    await db.commit()
    return {
        "message": "IOC validated and recorded",
        "ioc_id": str(ioc.id),
        "tx_hash": tx_hash,
        "block_number": block_number,
    }


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

    raw_key, expires_at = await _rotate_api_key(org)
    await db.commit()
    await invalidate_api_key_cache()
    try:
        await asyncio.to_thread(EmailService.send_api_key_email, org.email, org.name, raw_key)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Unable to send API key email: {exc}",
        )
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


@router.get("/malware-samples")
async def list_malware_samples(
    org_id: uuid.UUID | None = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_jwt),
):
    svc = AssetService(db)
    samples = await svc.list_malware_samples(org_id=org_id, limit=limit)
    return {
        "data": [MalwareSampleRead.model_validate(item) for item in samples],
        "meta": {"page_size": limit, "next_cursor": None},
        "error": None,
    }


@router.get("/threat-actors")
async def list_threat_actors(
    org_id: uuid.UUID | None = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_jwt),
):
    svc = AssetService(db)
    actors = await svc.list_threat_actors(org_id=org_id, limit=limit)
    return {
        "data": [ThreatActorRead.model_validate(item) for item in actors],
        "meta": {"page_size": limit, "next_cursor": None},
        "error": None,
    }


@router.get("/contributor-users")
async def list_contributor_users(
    org_id: uuid.UUID | None = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_jwt),
):
    svc = AssetService(db)
    users = await svc.list_contributor_users(org_id=org_id, limit=limit)
    return {
        "data": [ContributorUserRead.model_validate(item) for item in users],
        "meta": {"page_size": limit, "next_cursor": None},
        "error": None,
    }