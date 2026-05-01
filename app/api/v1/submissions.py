from fastapi import APIRouter, Depends, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.v1.deps import get_db, verify_api_key
from app.rate_limiter import limiter
from app.services.malware_service import MalwareService
from app.services.threat_actor_service import ThreatActorService
from app.schemas.malware import MalwareCreate, MalwareRead
from app.schemas.threat_actor import ThreatActorCreate, ThreatActorRead
import uuid

router = APIRouter()


@router.post("/malware/submit", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
async def submit_malware(
    request: Request,
    data: MalwareCreate,
    org_id: uuid.UUID = Depends(verify_api_key),
    db: AsyncSession = Depends(get_db),
):
    svc = MalwareService(db)
    sample = await svc.submit(data, org_id)
    return {"data": {"id": str(sample.id), "status": sample.status}, "meta": {}, "error": None}


@router.post("/threat-actors/submit", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
async def submit_threat_actor(
    request: Request,
    data: ThreatActorCreate,
    org_id: uuid.UUID = Depends(verify_api_key),
    db: AsyncSession = Depends(get_db),
):
    svc = ThreatActorService(db)
    ta = await svc.submit(data, org_id)
    return {"data": {"id": str(ta.id), "status": ta.status}, "meta": {}, "error": None}


@router.get("/malware")
async def list_malware(after: uuid.UUID | None = None, limit: int = 50, db: AsyncSession = Depends(get_db)):
    svc = MalwareService(db)
    items = await svc.list_validated(limit=limit)
    cursor = str(items[-1].id) if len(items) == limit else None
    return {"data": [MalwareRead.model_validate(i) for i in items], "meta": {"page_size": limit, "next_cursor": cursor}, "error": None}


@router.get("/threat-actors")
async def list_threat_actors(after: uuid.UUID | None = None, limit: int = 50, db: AsyncSession = Depends(get_db)):
    svc = ThreatActorService(db)
    items = await svc.list_validated(limit=limit)
    cursor = str(items[-1].id) if len(items) == limit else None
    return {"data": [ThreatActorRead.model_validate(i) for i in items], "meta": {"page_size": limit, "next_cursor": cursor}, "error": None}
