from fastapi import APIRouter, Depends
from sqlalchemy import String, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_db
from app.models.blockchain_record import BlockchainRecord
from app.models.ioc import IOC, IOCStatus
from app.models.malware_sample import MalwareSample, MalwareStatus
from app.models.threat_actor import ThreatActor, ThreatActorStatus


router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats")
async def public_dashboard_stats(db: AsyncSession = Depends(get_db)):
    ioc_total = await db.scalar(
        select(func.count()).select_from(IOC).where(
            IOC.status == IOCStatus.APPROVED,
            func.lower(cast(IOC.tlp, String)).in_(["green", "white"]),
        )
    )
    malware_total = await db.scalar(
        select(func.count()).select_from(MalwareSample).where(
            MalwareSample.status == MalwareStatus.approved,
            func.lower(cast(MalwareSample.tlp, String)).in_(["green", "white"]),
        )
    )
    actor_total = await db.scalar(
        select(func.count()).select_from(ThreatActor).where(
            ThreatActor.status == ThreatActorStatus.approved,
            func.lower(cast(ThreatActor.tlp, String)).in_(["green", "white"]),
        )
    )
    blockchain_total = await db.scalar(
        select(func.count())
        .select_from(BlockchainRecord)
        .join(IOC, BlockchainRecord.ioc_id == IOC.id)
        .where(
            IOC.status == IOCStatus.APPROVED,
            func.lower(cast(IOC.tlp, String)).in_(["green", "white"]),
        )
    )
    by_type_rows = await db.execute(
        select(IOC.type, func.count())
        .where(
            IOC.status == IOCStatus.APPROVED,
            func.lower(cast(IOC.tlp, String)).in_(["green", "white"]),
        )
        .group_by(IOC.type)
    )
    by_tlp_rows = await db.execute(
        select(IOC.tlp, func.count())
        .where(
            IOC.status == IOCStatus.APPROVED,
            func.lower(cast(IOC.tlp, String)).in_(["green", "white"]),
        )
        .group_by(IOC.tlp)
    )
    return {
        "total_iocs": int(ioc_total or 0),
        "total_threat_actors": int(actor_total or 0),
        "total_malware_samples": int(malware_total or 0),
        "total_blockchain_records": int(blockchain_total or 0),
        "by_type": {row[0].value if hasattr(row[0], "value") else str(row[0]): int(row[1]) for row in by_type_rows},
        "by_tlp": {str(row[0]): int(row[1]) for row in by_tlp_rows},
    }
