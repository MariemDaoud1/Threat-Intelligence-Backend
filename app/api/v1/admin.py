import asyncio
from datetime import datetime, timedelta, timezone
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_db, invalidate_api_key_cache, require_admin
from app.config import settings
from app.models.contributor_user import ContributorUser
from app.models.blockchain_record import BlockchainEventType
from app.models.ioc import IOC, IOCStatus
from app.models.malware_sample import MalwareSample, MalwareStatus
from app.models.organisation import Organisation, OrgStatus
from app.models.threat_actor import ThreatActor, ThreatActorStatus
from app.schemas.assets import MalwareSampleRead, ThreatActorRead
from app.schemas.ioc import IOCRead
from app.services.auth_service import AuthService
from app.services.email_service import EmailService
from app.services.blockchain_service import BlockchainService
from app.services.moderation_service import ModerationService
from app.services.trust_service import TrustService


router = APIRouter(prefix="/admin", tags=["Admin"])


class TrustScoreUpdateRequest(BaseModel):
    trust_score: int = Field(..., ge=0, le=100)


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


async def _get_org_or_404(db: AsyncSession, org_id: uuid.UUID) -> Organisation:
    org = await db.get(Organisation, org_id)
    if org is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")
    return org


async def _get_ioc_with_org(db: AsyncSession, ioc_id: uuid.UUID) -> tuple[IOC, Organisation]:
    query = (
        select(IOC, Organisation)
        .join(Organisation, Organisation.id == IOC.org_id)
        .where(IOC.id == ioc_id)
    )
    row = (await db.execute(query)).one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")
    return row[0], row[1]


async def _get_malware_with_org(db: AsyncSession, malware_id: uuid.UUID) -> tuple[MalwareSample, Organisation]:
    query = (
        select(MalwareSample, Organisation)
        .join(Organisation, Organisation.id == MalwareSample.org_id)
        .where(MalwareSample.id == malware_id)
    )
    row = (await db.execute(query)).one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Malware sample not found")
    return row[0], row[1]


async def _get_threat_actor_with_org(db: AsyncSession, actor_id: uuid.UUID) -> tuple[ThreatActor, Organisation]:
    query = (
        select(ThreatActor, Organisation)
        .join(Organisation, Organisation.id == ThreatActor.org_id)
        .where(ThreatActor.id == actor_id)
    )
    row = (await db.execute(query)).one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat actor not found")
    return row[0], row[1]


def _status_value(value: object) -> str:
    return value.value if hasattr(value, "value") else str(value)


@router.get("/organisations")
async def list_organisations(
    db: AsyncSession = Depends(get_db),
    admin: ContributorUser = Depends(require_admin),
):
    result = await db.execute(select(Organisation).order_by(Organisation.created_at.desc()))
    rows = [
        {
            "id": str(org.id),
            "name": org.name,
            "siret": org.siret,
            "email": org.email,
            "website": org.website,
            "description": org.description,
            "country": org.country,
            "trust_score": org.trust_score,
            "status": _status_value(org.status),
            "created_at": org.created_at,
        }
        for org in result.scalars().all()
    ]
    return {"total": len(rows), "items": rows}


@router.post("/organisations/{org_id}/trust-score")
async def update_trust_score(
    org_id: uuid.UUID,
    payload: TrustScoreUpdateRequest,
    db: AsyncSession = Depends(get_db),
    admin: ContributorUser = Depends(require_admin),
):
    org = await _get_org_or_404(db, org_id)
    TrustService.set_score(org, payload.trust_score)
    await db.commit()
    await db.refresh(org)
    return {
        "id": str(org.id),
        "trust_score": org.trust_score,
        "status": _status_value(org.status),
    }


@router.post("/approve/{org_id}")
async def approve_organisation(
    org_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    admin: ContributorUser = Depends(require_admin),
):
    result = await db.execute(select(Organisation).where(Organisation.id == org_id))
    org = result.scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=404, detail="Organisation not found")
    if org.status == OrgStatus.approved:
        raise HTTPException(status_code=400, detail="Organisation already approved")

    temporary_password = AuthService.generate_temp_password()
    contributor_result = await db.execute(
        select(ContributorUser).where(
            ContributorUser.org_id == org.id,
            ContributorUser.role == "contributor",
        )
    )
    contributor = contributor_result.scalar_one_or_none()
    if contributor is None:
        contributor = ContributorUser(
            org_id=org.id,
            email=org.email,
            hashed_password=AuthService.hash_password(temporary_password),
            role="contributor",
            must_change_password=True,
            is_active=True,
        )
        db.add(contributor)
    else:
        contributor.email = org.email
        contributor.hashed_password = AuthService.hash_password(temporary_password)
        contributor.must_change_password = True
        contributor.is_active = True

    org.status = OrgStatus.approved
    raw_key, expires_at = await _rotate_api_key(org)

    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise
    await invalidate_api_key_cache()

    email_warning: str | None = None
    try:
        await asyncio.to_thread(EmailService.send_api_key_email, org.email, org.name, raw_key)
        await asyncio.to_thread(EmailService.send_contributor_welcome_email, org.email, org.name, temporary_password)
    except Exception as exc:
        email_warning = f"Organisation approved but email delivery failed: {exc}"

    response = {
        "id": str(org.id),
        "status": org.status.value,
        "message": "Organisation approved and credentials sent by email",
        "api_key_expires_at": expires_at,
    }
    if email_warning:
        response["message"] = "Organisation approved but email delivery failed"
        response["email_warning"] = email_warning
    return response


@router.post("/revoke/{org_id}")
async def revoke_organisation(
    org_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    admin: ContributorUser = Depends(require_admin),
):
    result = await db.execute(select(Organisation).where(Organisation.id == org_id))
    org = result.scalar_one_or_none()
    if org is None:
        raise HTTPException(status_code=404, detail="Organisation not found")

    org.status = OrgStatus.revoked
    now = datetime.now(timezone.utc)
    org.api_key_revoked_at = now
    org.api_key_expires_at = now

    contrib_result = await db.execute(
        select(ContributorUser).where(
            ContributorUser.org_id == org.id,
            ContributorUser.role == "contributor",
        )
    )
    contributor = contrib_result.scalar_one_or_none()
    if contributor is not None:
        contributor.is_active = False

    await db.commit()
    await invalidate_api_key_cache()
    return {"id": str(org.id), "status": org.status.value, "message": "Organisation revoked successfully"}


@router.get("/stats")
async def admin_stats(
    db: AsyncSession = Depends(get_db),
    admin: ContributorUser = Depends(require_admin),
):
    ioc_total = await db.scalar(select(func.count()).select_from(IOC))
    malware_total = await db.scalar(select(func.count()).select_from(MalwareSample))
    actor_total = await db.scalar(select(func.count()).select_from(ThreatActor))
    pending_iocs = await db.scalar(select(func.count()).select_from(IOC).where(IOC.status == IOCStatus.PENDING))
    pending_malware = await db.scalar(
        select(func.count()).select_from(MalwareSample).where(MalwareSample.status == MalwareStatus.pending)
    )
    pending_actors = await db.scalar(
        select(func.count()).select_from(ThreatActor).where(ThreatActor.status == ThreatActorStatus.pending)
    )

    by_type_rows = await db.execute(select(IOC.type, func.count()).group_by(IOC.type))
    by_tlp_rows = await db.execute(select(IOC.tlp, func.count()).group_by(IOC.tlp))

    return {
        "total_iocs": int(ioc_total or 0),
        "total_malware_samples": int(malware_total or 0),
        "total_threat_actors": int(actor_total or 0),
        "pending_iocs": int(pending_iocs or 0),
        "pending_malware_samples": int(pending_malware or 0),
        "pending_threat_actors": int(pending_actors or 0),
        "pending_submissions": int((pending_iocs or 0) + (pending_malware or 0) + (pending_actors or 0)),
        "by_type": {row[0].value if hasattr(row[0], "value") else str(row[0]): int(row[1]) for row in by_type_rows},
        "by_tlp": {str(row[0]): int(row[1]) for row in by_tlp_rows},
    }


@router.get("/iocs")
async def list_admin_iocs(
    db: AsyncSession = Depends(get_db),
    admin: ContributorUser = Depends(require_admin),
):
    result = await db.execute(select(IOC).order_by(IOC.submitted_at.desc()))
    return [IOCRead.model_validate(item).model_dump() for item in result.scalars().all()]


@router.get("/malware")
async def list_admin_malware(
    db: AsyncSession = Depends(get_db),
    admin: ContributorUser = Depends(require_admin),
):
    result = await db.execute(select(MalwareSample).order_by(MalwareSample.submitted_at.desc()))
    return [MalwareSampleRead.model_validate(item).model_dump() for item in result.scalars().all()]


@router.get("/threat-actors")
async def list_admin_threat_actors(
    db: AsyncSession = Depends(get_db),
    admin: ContributorUser = Depends(require_admin),
):
    result = await db.execute(select(ThreatActor).order_by(ThreatActor.submitted_at.desc()))
    return [ThreatActorRead.model_validate(item).model_dump() for item in result.scalars().all()]


@router.get("/moderation/iocs")
async def list_pending_iocs(
    db: AsyncSession = Depends(get_db),
    admin: ContributorUser = Depends(require_admin),
):
    result = await db.execute(select(IOC).where(IOC.status == IOCStatus.PENDING).order_by(IOC.submitted_at.desc()))
    return [IOCRead.model_validate(item).model_dump() for item in result.scalars().all()]


@router.post("/moderation/iocs/{ioc_id}/approve")
async def approve_ioc(
    ioc_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    admin: ContributorUser = Depends(require_admin),
):
    item, org = await _get_ioc_with_org(db, ioc_id)
    ModerationService.approve_pending(
        item=item,
        org=org,
        pending_status=IOCStatus.PENDING,
        approved_status=IOCStatus.APPROVED,
        approved_at_field="validated_at",
    )
    await db.commit()
    await db.refresh(item)
    blockchain_service = BlockchainService(db)
    await blockchain_service.record_ioc_event(ioc=item, event_type=BlockchainEventType.IOC_APPROVED)
    return IOCRead.model_validate(item).model_dump()


@router.post("/moderation/iocs/{ioc_id}/reject")
async def reject_ioc(
    ioc_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    admin: ContributorUser = Depends(require_admin),
):
    item, org = await _get_ioc_with_org(db, ioc_id)
    ModerationService.reject_pending(
        item=item,
        org=org,
        pending_status=IOCStatus.PENDING,
        rejected_status=IOCStatus.REJECTED,
        rejected_at_field="rejected_at",
    )
    await db.commit()
    await db.refresh(item)
    return IOCRead.model_validate(item).model_dump()


@router.get("/moderation/malware")
async def list_pending_malware(
    db: AsyncSession = Depends(get_db),
    admin: ContributorUser = Depends(require_admin),
):
    result = await db.execute(
        select(MalwareSample)
        .where(MalwareSample.status == MalwareStatus.pending)
        .order_by(MalwareSample.submitted_at.desc())
    )
    return [MalwareSampleRead.model_validate(item).model_dump() for item in result.scalars().all()]


@router.post("/moderation/malware/{malware_id}/approve")
async def approve_malware(
    malware_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    admin: ContributorUser = Depends(require_admin),
):
    item, org = await _get_malware_with_org(db, malware_id)
    ModerationService.approve_pending(
        item=item,
        org=org,
        pending_status=MalwareStatus.pending,
        approved_status=MalwareStatus.approved,
    )
    await db.commit()
    await db.refresh(item)
    return MalwareSampleRead.model_validate(item).model_dump()


@router.post("/moderation/malware/{malware_id}/reject")
async def reject_malware(
    malware_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    admin: ContributorUser = Depends(require_admin),
):
    item, org = await _get_malware_with_org(db, malware_id)
    ModerationService.reject_pending(
        item=item,
        org=org,
        pending_status=MalwareStatus.pending,
        rejected_status=MalwareStatus.rejected,
    )
    await db.commit()
    await db.refresh(item)
    return MalwareSampleRead.model_validate(item).model_dump()


@router.get("/moderation/threat-actors")
async def list_pending_threat_actors(
    db: AsyncSession = Depends(get_db),
    admin: ContributorUser = Depends(require_admin),
):
    result = await db.execute(
        select(ThreatActor)
        .where(ThreatActor.status == ThreatActorStatus.pending)
        .order_by(ThreatActor.submitted_at.desc())
    )
    return [ThreatActorRead.model_validate(item).model_dump() for item in result.scalars().all()]


@router.post("/moderation/threat-actors/{actor_id}/approve")
async def approve_threat_actor(
    actor_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    admin: ContributorUser = Depends(require_admin),
):
    item, org = await _get_threat_actor_with_org(db, actor_id)
    ModerationService.approve_pending(
        item=item,
        org=org,
        pending_status=ThreatActorStatus.pending,
        approved_status=ThreatActorStatus.approved,
    )
    await db.commit()
    await db.refresh(item)
    return ThreatActorRead.model_validate(item).model_dump()


@router.post("/moderation/threat-actors/{actor_id}/reject")
async def reject_threat_actor(
    actor_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    admin: ContributorUser = Depends(require_admin),
):
    item, org = await _get_threat_actor_with_org(db, actor_id)
    ModerationService.reject_pending(
        item=item,
        org=org,
        pending_status=ThreatActorStatus.pending,
        rejected_status=ThreatActorStatus.rejected,
    )
    await db.commit()
    await db.refresh(item)
    return ThreatActorRead.model_validate(item).model_dump()
