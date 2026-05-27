from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
import uuid

from app.api.v1.deps import get_db, verify_api_key
from app.models.ioc import IOC, IOCStatus, IOCType
from app.rate_limiter import limiter
from app.schemas.ioc import IOCCreate, IOCRead
from app.services.ioc_service import IOCService


router = APIRouter()


PUBLIC_STATUS_FILTERS = {"approved", "validated"}


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
    return {"data": {"id": str(ioc.id), "status": ioc.status.value}, "meta": {}, "error": None}


@router.get("/iocs")
async def list_public_iocs(
    search: str | None = None,
    type: str | None = None,
    tlp: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    page: int | None = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(IOC).where(
        IOC.status == IOCStatus.APPROVED,
        func.lower(cast(IOC.tlp, String)).in_(["green", "white"]),
    )
    if search:
        like = f"%{search.lower()}%"
        stmt = stmt.where(
            or_(
                cast(IOC.value, String).ilike(like),
                cast(IOC.description, String).ilike(like),
            )
        )
    if type:
        try:
            stmt = stmt.where(IOC.type == IOCType(type))
        except ValueError:
            return []
    if tlp:
        stmt = stmt.where(func.lower(cast(IOC.tlp, String)) == tlp.lower())
    if status_filter:
        if status_filter.lower() not in PUBLIC_STATUS_FILTERS:
            return []
    safe_limit = min(max(limit, 1), 200)
    stmt = stmt.order_by(IOC.submitted_at.desc()).limit(safe_limit)
    if page and page > 1:
        stmt = stmt.offset((page - 1) * safe_limit)
    result = await db.execute(stmt)
    return [IOCRead.model_validate(item) for item in result.scalars().all()]


@router.get("/iocs/{ioc_id}")
async def get_public_ioc(ioc_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    stmt = select(IOC).options(selectinload(IOC.blockchain_records)).where(IOC.id == ioc_id)
    result = await db.execute(stmt)
    item = result.scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=404, detail="IOC not found")
    tlp_value = (item.tlp or "").lower()
    if item.status != IOCStatus.APPROVED or tlp_value not in {"green", "white"}:
        raise HTTPException(status_code=404, detail="IOC not found")
    payload = IOCRead.model_validate(item).model_dump()
    payload["blockchain_records"] = [
        {
            "id": str(record.id),
            "ioc_id": str(record.ioc_id),
            "tx_hash": record.tx_hash,
            "block_number": record.block_number,
            "event_type": record.event_type.value if hasattr(record.event_type, "value") else str(record.event_type),
            "recorded_at": record.recorded_at,
        }
        for record in item.blockchain_records
    ]
    return payload
