from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import String, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ioc import IOC, IOCStatus
from app.models.organisation import Organisation
from app.schemas.ioc import IOCCreate
from app.services.moderation_service import ModerationService
from app.services.trust_service import TrustService


class IOCService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _get_org(self, org_id: UUID) -> Organisation:
        org = await self.db.get(Organisation, org_id)
        if org is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")
        return org

    async def determine_initial_status(self, org_id: UUID) -> IOCStatus:
        org = await self._get_org(org_id)
        return ModerationService.initial_status_for_org(
            org,
            pending_status=IOCStatus.PENDING,
            approved_status=IOCStatus.APPROVED,
        )

    async def submit(self, data: IOCCreate, org_id: UUID) -> IOC:
        org = await self._get_org(org_id)
        initial_status = ModerationService.initial_status_for_org(
            org,
            pending_status=IOCStatus.PENDING,
            approved_status=IOCStatus.APPROVED,
        )
        if initial_status == IOCStatus.APPROVED:
            TrustService.apply_delta(org, TrustService.APPROVAL_DELTA)
        ioc = IOC(
            type=data.type,
            value=data.value,
            description=data.description,
            org_id=org_id,
            tlp=(data.tlp or "green").lower(),
            confidence=data.confidence,
            first_seen=data.first_seen,
            last_seen=data.last_seen,
            tags=data.tags or [],
            source_context=data.source_context,
            status=initial_status,
            validated_at=datetime.now(timezone.utc) if initial_status == IOCStatus.APPROVED else None,
        )
        self.db.add(ioc)
        await self.db.commit()
        await self.db.refresh(ioc)
        return ioc

    async def get_public(self, limit: int = 50) -> list[IOC]:
        q = (
            select(IOC)
            .where(IOC.status == IOCStatus.APPROVED)
            .where(func.lower(cast(IOC.tlp, String)).in_(["green", "white"]))
            .order_by(IOC.submitted_at.desc())
            .limit(limit)
        )
        result = await self.db.execute(q)
        return result.scalars().all()

    async def get_validated(self, after: UUID | None = None, limit: int = 50) -> list[IOC]:
        # Backward-compatible alias used by older call sites.
        return await self.get_public(limit=limit)
