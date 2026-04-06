from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.ioc import IOC, IOCStatus
from app.schemas.ioc import IOCCreate

class IOCService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def submit(self, data: IOCCreate, org_id: UUID) -> IOC:
        ioc = IOC(
            type=data.type,
            value=data.value,
            description=data.description,
            org_id=org_id,
            status=IOCStatus.PENDING,
        )
        self.db.add(ioc)
        await self.db.commit()
        await self.db.refresh(ioc)
        return ioc
    
    #fetching validated IOCs with cursor-based pagination
    async def get_validated(self, after: UUID | None = None, limit: int = 50) -> list[IOC]:
        q = select(IOC)\
            .where(IOC.status == IOCStatus.VALIDATED)\
            .order_by(IOC.submitted_at.desc())\
            .limit(limit)

        if after:
            cursor = await self.db.get(IOC, after)
            if cursor:
                q = q.where(IOC.submitted_at < cursor.submitted_at)

        result = await self.db.execute(q)
        return result.scalars().all()