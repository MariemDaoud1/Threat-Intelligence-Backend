from datetime import datetime, timezone
import ipaddress
from urllib.parse import urlparse
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import String, cast, select
from app.models.organisation import Organisation
from app.models.ioc import IOC, IOCStatus
from app.schemas.ioc import IOCCreate

class IOCService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def determine_initial_status(self, org_id: UUID, data: IOCCreate) -> IOCStatus:
        org = await self.db.get(Organisation, org_id)
        if org is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organisation not found",
            )

        if org.trust_score >= 50 and not self._is_suspicious(data):
            return IOCStatus.VALIDATED

        return IOCStatus.PENDING

    def _is_suspicious(self, data: IOCCreate) -> bool:
        value = data.value.strip()

        if data.type.value == "ip":
            try:
                ip = ipaddress.ip_address(value)
                return any((ip.is_private, ip.is_loopback, ip.is_multicast, ip.is_reserved, ip.is_unspecified))
            except ValueError:
                return True

        if data.type.value == "url":
            parsed = urlparse(value)
            hostname = (parsed.hostname or "").lower()
            if parsed.scheme not in {"http", "https"} or not hostname:
                return True
            if hostname in {"localhost", "127.0.0.1", "0.0.0.0"}:
                return True
            try:
                host_ip = ipaddress.ip_address(hostname)
                return any((host_ip.is_private, host_ip.is_loopback, host_ip.is_multicast, host_ip.is_reserved, host_ip.is_unspecified))
            except ValueError:
                return hostname.endswith(".local") or "@" in value

        if data.type.value == "hash":
            return len(set(value)) == 1 or value.lower() in {"0" * len(value), "f" * len(value)}

        if data.type.value == "email":
            local_part, _, domain = value.partition("@"); domain = domain.lower()
            return not local_part or domain in {"localhost", "localdomain"} or domain.endswith(".local")

        return False

    async def submit(self, data: IOCCreate, org_id: UUID) -> IOC:
        initial_status = await self.determine_initial_status(org_id, data)
        ioc = IOC(
            type=data.type,
            value=data.value,
            description=data.description,
            org_id=org_id,
            status=initial_status,
            validated_at=datetime.now(timezone.utc) if initial_status == IOCStatus.VALIDATED else None,
        )
        self.db.add(ioc)
        await self.db.commit()
        await self.db.refresh(ioc)
        return ioc
    
    #fetching validated IOCs with cursor-based pagination
    async def get_validated(self, after: UUID | None = None, limit: int = 50) -> list[IOC]:
        # Keep compatibility with legacy enum labels already present in some databases.
        validated_labels = ["validated", "VALIDATED", "VALIDaTED"]
        q = select(IOC)\
            .where(cast(IOC.status, String).in_(validated_labels))\
            .order_by(IOC.submitted_at.desc())\
            .limit(limit)

        if after:
            cursor = await self.db.get(IOC, after)
            if cursor:
                q = q.where(IOC.submitted_at < cursor.submitted_at)

        result = await self.db.execute(q)
        return result.scalars().all()