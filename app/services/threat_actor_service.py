from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import String, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.organisation import Organisation
from app.models.threat_actor import ThreatActor, ThreatActorStatus
from app.schemas.threat_actor import ThreatActorCreate
from app.services.moderation_service import ModerationService
from app.services.trust_service import TrustService


class ThreatActorService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _get_org(self, org_id) -> Organisation:
        org = await self.db.get(Organisation, org_id)
        if org is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")
        return org

    async def _determine_initial_status(self, org_id) -> ThreatActorStatus:
        org = await self._get_org(org_id)
        return ModerationService.initial_status_for_org(
            org,
            pending_status=ThreatActorStatus.pending,
            approved_status=ThreatActorStatus.approved,
        )

    async def _ensure_unique_name(self, data: ThreatActorCreate) -> None:
        q = select(ThreatActor).where(ThreatActor.name == data.name)
        res = await self.db.execute(q)
        if res.scalars().first():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Threat actor with that name already exists")

    async def submit(self, data: ThreatActorCreate, org_id):
        await self._ensure_unique_name(data)
        org = await self._get_org(org_id)
        initial_status = ModerationService.initial_status_for_org(
            org,
            pending_status=ThreatActorStatus.pending,
            approved_status=ThreatActorStatus.approved,
        )
        if initial_status == ThreatActorStatus.approved:
            TrustService.apply_delta(org, TrustService.APPROVAL_DELTA)
        ta = ThreatActor(
            name=data.name,
            aliases=data.aliases or [],
            motivation=data.motivation,
            country=data.country,
            description=data.description,
            org_id=org_id,
            tlp=(data.tlp or "green").lower(),
            status=initial_status,
            submitted_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        self.db.add(ta)
        await self.db.commit()
        await self.db.refresh(ta)
        return ta

    async def list_public(self, limit: int = 50):
        q = (
            select(ThreatActor)
            .where(ThreatActor.status == ThreatActorStatus.approved)
            .where(func.lower(cast(ThreatActor.tlp, String)).in_(["green", "white"]))
            .order_by(ThreatActor.submitted_at.desc())
            .limit(limit)
        )
        res = await self.db.execute(q)
        return res.scalars().all()

    async def list_validated(self, limit: int = 50):
        # Backward-compatible alias used by older call sites.
        return await self.list_public(limit=limit)
