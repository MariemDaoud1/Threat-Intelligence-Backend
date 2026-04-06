from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.v1.deps import get_db
from app.schemas.ioc import IOCCreate, IOCRead
from app.services.ioc_service import IOCService
import uuid

router = APIRouter()

@router.post("/iocs/submit", status_code=status.HTTP_202_ACCEPTED)
async def submit_ioc(
    data: IOCCreate,
    db: AsyncSession = Depends(get_db),
):
    fake_org_id = uuid.UUID("00000000-0000-0000-0000-000000000001")  
    svc = IOCService(db)
    ioc = await svc.submit(data, fake_org_id)
    return {"data": {"id": str(ioc.id), "status": ioc.status}, "meta": {}, "error": None}

@router.get("/iocs")
async def list_iocs(
    after: uuid.UUID | None = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    svc = IOCService(db)
    iocs = await svc.get_validated(after=after, limit=limit)
    cursor = str(iocs[-1].id) if len(iocs) == limit else None
    return {
        "data": [IOCRead.model_validate(i) for i in iocs],
        "meta": {"page_size": limit, "next_cursor": cursor},
        "error": None,
    }