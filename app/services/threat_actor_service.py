from datetime import datetime, timezone
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.threat_actor import ThreatActor, ThreatActorStatus
from app.models.organisation import Organisation
from app.schemas.threat_actor import ThreatActorCreate


class ThreatActorService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _determine_initial_status(self, org_id, data: ThreatActorCreate) -> ThreatActorStatus:
        org = await self.db.get(Organisation, org_id)
        if org is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")
        return ThreatActorStatus.validated if org.trust_score >= 50 else ThreatActorStatus.pending

    async def _ensure_unique_name(self, data: ThreatActorCreate) -> None:
        q = select(ThreatActor).where(ThreatActor.name == data.name)
        res = await self.db.execute(q)
        if res.scalars().first():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Threat actor with that name already exists")

    async def submit(self, data: ThreatActorCreate, org_id):
        await self._ensure_unique_name(data)
        initial_status = await self._determine_initial_status(org_id, data)
        ta = ThreatActor(
            name=data.name,
            aliases=data.aliases or [],
            motivation=data.motivation,
            country=data.country,
            description=data.description,
            org_id=org_id,
            tlp=data.tlp or "green",
            status=initial_status,
            submitted_at=datetime.now(timezone.utc).replace(tzinfo=None),
        )
        self.db.add(ta)
        await self.db.commit()
        await self.db.refresh(ta)
        return ta

    async def list_validated(self, limit: int = 50):
        q = select(ThreatActor).where(ThreatActor.status == ThreatActorStatus.validated).order_by(ThreatActor.submitted_at.desc()).limit(limit)
        res = await self.db.execute(q)
        return res.scalars().all()
