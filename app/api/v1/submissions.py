import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_db, verify_api_key
from app.models.malware_sample import MalwareSample, MalwareStatus
from app.models.threat_actor import ThreatActor, ThreatActorStatus
from app.rate_limiter import limiter
from app.schemas.malware import MalwareCreate, MalwareRead
from app.schemas.threat_actor import ThreatActorCreate, ThreatActorRead
from app.services.malware_service import MalwareService
from app.services.threat_actor_service import ThreatActorService


router = APIRouter()


PUBLIC_STATUS_FILTERS = {"approved", "validated"}


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
    return {"data": {"id": str(sample.id), "status": sample.status.value}, "meta": {}, "error": None}


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
    return {"data": {"id": str(ta.id), "status": ta.status.value}, "meta": {}, "error": None}


@router.get("/malware")
async def list_public_malware(
    search: str | None = None,
    tlp: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(MalwareSample).where(
        MalwareSample.status == MalwareStatus.approved,
        func.lower(cast(MalwareSample.tlp, String)).in_(["green", "white"]),
    )
    if search:
        like = f"%{search.lower()}%"
        stmt = stmt.where(
            or_(
                cast(MalwareSample.name, String).ilike(like),
                cast(MalwareSample.description, String).ilike(like),
            )
        )
    if tlp:
        stmt = stmt.where(func.lower(cast(MalwareSample.tlp, String)) == tlp.lower())
    if status_filter and status_filter.lower() not in PUBLIC_STATUS_FILTERS:
        return []
    stmt = stmt.order_by(MalwareSample.submitted_at.desc()).limit(min(max(limit, 1), 200))
    result = await db.execute(stmt)
    return [MalwareRead.model_validate(i) for i in result.scalars().all()]


@router.get("/malware/{malware_id}")
async def get_public_malware(malware_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    stmt = select(MalwareSample).where(MalwareSample.id == malware_id)
    result = await db.execute(stmt)
    item = result.scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=404, detail="Malware sample not found")
    tlp_value = (item.tlp or "").lower()
    if item.status != MalwareStatus.approved or tlp_value not in {"green", "white"}:
        raise HTTPException(status_code=404, detail="Malware sample not found")
    return MalwareRead.model_validate(item)


@router.get("/threat-actors")
async def list_public_threat_actors(
    search: str | None = None,
    tlp: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ThreatActor).where(
        ThreatActor.status == ThreatActorStatus.approved,
        func.lower(cast(ThreatActor.tlp, String)).in_(["green", "white"]),
    )
    if search:
        like = f"%{search.lower()}%"
        stmt = stmt.where(
            or_(
                cast(ThreatActor.name, String).ilike(like),
                cast(ThreatActor.description, String).ilike(like),
            )
        )
    if tlp:
        stmt = stmt.where(func.lower(cast(ThreatActor.tlp, String)) == tlp.lower())
    if status_filter and status_filter.lower() not in PUBLIC_STATUS_FILTERS:
        return []
    stmt = stmt.order_by(ThreatActor.submitted_at.desc()).limit(min(max(limit, 1), 200))
    result = await db.execute(stmt)
    return [ThreatActorRead.model_validate(i) for i in result.scalars().all()]


@router.get("/threat-actors/{threat_actor_id}")
async def get_public_threat_actor(threat_actor_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    stmt = select(ThreatActor).where(ThreatActor.id == threat_actor_id)
    result = await db.execute(stmt)
    item = result.scalar_one_or_none()
    if item is None:
        raise HTTPException(status_code=404, detail="Threat actor not found")
    tlp_value = (item.tlp or "").lower()
    if item.status != ThreatActorStatus.approved or tlp_value not in {"green", "white"}:
        raise HTTPException(status_code=404, detail="Threat actor not found")
    return ThreatActorRead.model_validate(item)
