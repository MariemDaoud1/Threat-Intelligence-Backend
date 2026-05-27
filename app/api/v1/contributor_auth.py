from datetime import datetime, timezone
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_db, require_contributor
from app.models.blockchain_record import BlockchainEventType
from app.models.contributor_user import ContributorUser
from app.models.ioc import IOC, IOCStatus
from app.models.malware_sample import MalwareSample, MalwareStatus
from app.models.organisation import Organisation
from app.models.threat_actor import ThreatActor, ThreatActorStatus
from app.schemas.ioc import IOCCreate, IOCRead
from app.schemas.malware import MalwareCreate, MalwareRead
from app.schemas.threat_actor import ThreatActorCreate, ThreatActorRead
from app.services.auth_service import AuthService, create_access_token
from app.services.blockchain_service import BlockchainService
from app.services.ioc_service import IOCService
from app.services.malware_service import MalwareService
from app.services.moderation_service import ModerationService
from app.services.threat_actor_service import ThreatActorService


router = APIRouter(prefix="/contributor", tags=["Contributors"])


class ContributorLogin(BaseModel):
    email: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


def _to_contributor_me(user: ContributorUser) -> dict:
    organisation_payload = None
    if user.organisation is not None:
        organisation_payload = {
            "id": str(user.organisation.id),
            "name": user.organisation.name,
            "siret": user.organisation.siret,
            "email": user.organisation.email,
            "website": user.organisation.website,
            "description": user.organisation.description,
            "country": user.organisation.country,
            "trust_score": user.organisation.trust_score,
            "status": user.organisation.status.value if hasattr(user.organisation.status, "value") else str(user.organisation.status),
            "created_at": user.organisation.created_at,
        }

    return {
        "id": str(user.id),
        "email": user.email,
        "org_id": str(user.org_id) if user.org_id else "",
        "organisation": organisation_payload,
        "must_change_password": user.must_change_password,
    }


async def _get_user_org(db: AsyncSession, org_id: uuid.UUID) -> Organisation:
    org = await db.get(Organisation, org_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")
    return org


@router.post("/login")
async def login(payload: ContributorLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(ContributorUser).where(
            ContributorUser.email == payload.email,
            ContributorUser.role == "contributor",
        )
    )
    user = result.scalar_one_or_none()
    if user is None or not AuthService.verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Contributor account is inactive")

    token = create_access_token(subject=str(user.id), role="contributor")
    return {
        "access_token": token,
        "token_type": "bearer",
        "must_change_password": user.must_change_password,
    }


@router.post("/change-password")
async def change_password(
    payload: ChangePasswordRequest,
    user: ContributorUser = Depends(require_contributor),
    db: AsyncSession = Depends(get_db),
):
    if not AuthService.verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password incorrect")

    user.hashed_password = AuthService.hash_password(payload.new_password)
    user.must_change_password = False
    await db.commit()
    return {"message": "Password changed successfully"}


@router.get("/me")
async def me(user: ContributorUser = Depends(require_contributor)):
    return _to_contributor_me(user)


@router.get("/iocs")
async def list_own_iocs(
    db: AsyncSession = Depends(get_db),
    user: ContributorUser = Depends(require_contributor),
):
    result = await db.execute(select(IOC).where(IOC.org_id == user.org_id).order_by(IOC.submitted_at.desc()))
    return [IOCRead.model_validate(item) for item in result.scalars().all()]


@router.post("/iocs")
async def create_ioc(
    payload: IOCCreate,
    db: AsyncSession = Depends(get_db),
    user: ContributorUser = Depends(require_contributor),
):
    svc = IOCService(db)
    item = await svc.submit(payload, user.org_id)
    return IOCRead.model_validate(item)


@router.post("/iocs/{ioc_id}/false-positive")
async def mark_ioc_false_positive(
    ioc_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: ContributorUser = Depends(require_contributor),
):
    result = await db.execute(select(IOC).where(and_(IOC.id == ioc_id, IOC.org_id == user.org_id)))
    item = result.scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")
    org = await _get_user_org(db, user.org_id)
    ModerationService.mark_false_positive(
        item=item,
        org=org,
        false_positive_status=IOCStatus.FALSE_POSITIVE,
        blocked_statuses={IOCStatus.FALSE_POSITIVE, IOCStatus.REJECTED, IOCStatus.REVOKED},
    )
    await db.commit()
    await db.refresh(item)
    blockchain_service = BlockchainService(db)
    await blockchain_service.record_ioc_event(ioc=item, event_type=BlockchainEventType.IOC_FALSE_POSITIVE)
    return IOCRead.model_validate(item)


@router.get("/malware")
async def list_own_malware(
    db: AsyncSession = Depends(get_db),
    user: ContributorUser = Depends(require_contributor),
):
    result = await db.execute(
        select(MalwareSample).where(MalwareSample.org_id == user.org_id).order_by(MalwareSample.submitted_at.desc())
    )
    return [MalwareRead.model_validate(item) for item in result.scalars().all()]


@router.post("/malware")
async def create_malware(
    payload: MalwareCreate,
    db: AsyncSession = Depends(get_db),
    user: ContributorUser = Depends(require_contributor),
):
    svc = MalwareService(db)
    item = await svc.submit(payload, user.org_id)
    return MalwareRead.model_validate(item)


@router.post("/malware/{malware_id}/false-positive")
async def mark_malware_false_positive(
    malware_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: ContributorUser = Depends(require_contributor),
):
    result = await db.execute(
        select(MalwareSample).where(and_(MalwareSample.id == malware_id, MalwareSample.org_id == user.org_id))
    )
    item = result.scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Malware sample not found")
    org = await _get_user_org(db, user.org_id)
    ModerationService.mark_false_positive(
        item=item,
        org=org,
        false_positive_status=MalwareStatus.false_positive,
        blocked_statuses={MalwareStatus.false_positive, MalwareStatus.rejected},
    )
    await db.commit()
    await db.refresh(item)
    return MalwareRead.model_validate(item)


@router.get("/threat-actors")
async def list_own_threat_actors(
    db: AsyncSession = Depends(get_db),
    user: ContributorUser = Depends(require_contributor),
):
    result = await db.execute(
        select(ThreatActor).where(ThreatActor.org_id == user.org_id).order_by(ThreatActor.submitted_at.desc())
    )
    return [ThreatActorRead.model_validate(item) for item in result.scalars().all()]


@router.post("/threat-actors")
async def create_threat_actor(
    payload: ThreatActorCreate,
    db: AsyncSession = Depends(get_db),
    user: ContributorUser = Depends(require_contributor),
):
    svc = ThreatActorService(db)
    item = await svc.submit(payload, user.org_id)
    return ThreatActorRead.model_validate(item)


@router.post("/threat-actors/{threat_actor_id}/false-positive")
async def mark_threat_actor_false_positive(
    threat_actor_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: ContributorUser = Depends(require_contributor),
):
    result = await db.execute(
        select(ThreatActor).where(and_(ThreatActor.id == threat_actor_id, ThreatActor.org_id == user.org_id))
    )
    item = result.scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat actor not found")
    org = await _get_user_org(db, user.org_id)
    ModerationService.mark_false_positive(
        item=item,
        org=org,
        false_positive_status=ThreatActorStatus.false_positive,
        blocked_statuses={ThreatActorStatus.false_positive, ThreatActorStatus.rejected},
    )
    await db.commit()
    await db.refresh(item)
    return ThreatActorRead.model_validate(item)
