from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.contributor_user import ContributorUser
from app.models.malware_sample import MalwareSample
from app.models.threat_actor import ThreatActor


class AssetService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_malware_samples(self, org_id: UUID | None = None, limit: int = 50) -> list[MalwareSample]:
        stmt = select(MalwareSample).order_by(MalwareSample.submitted_at.desc()).limit(limit)
        if org_id is not None:
            stmt = stmt.where(MalwareSample.org_id == org_id)
        result = await self.db.execute(stmt)
        return result.scalars().all()

    async def list_threat_actors(self, org_id: UUID | None = None, limit: int = 50) -> list[ThreatActor]:
        stmt = select(ThreatActor).order_by(ThreatActor.submitted_at.desc()).limit(limit)
        if org_id is not None:
            stmt = stmt.where(ThreatActor.org_id == org_id)
        result = await self.db.execute(stmt)
        return result.scalars().all()

    async def list_contributor_users(self, org_id: UUID | None = None, limit: int = 50) -> list[ContributorUser]:
        stmt = select(ContributorUser).order_by(ContributorUser.created_at.desc()).limit(limit)
        if org_id is not None:
            stmt = stmt.where(ContributorUser.org_id == org_id)
        result = await self.db.execute(stmt)
        return result.scalars().all()
