from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.v1.deps import get_db, verify_api_key
from app.schemas.ioc import IOCCreate, IOCRead
from app.services.ioc_service import IOCService
from app.rate_limiter import limiter
import uuid

router = APIRouter()

@router.post("/iocs/submit", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("10/minute")
async def submit_ioc(
    request: Request,
    data: IOCCreate,
    org_id: uuid.UUID = Depends(verify_api_key),
    db: AsyncSession = Depends(get_db),
):
    svc = IOCService(db)
    ioc = await svc.submit(data, org_id)
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