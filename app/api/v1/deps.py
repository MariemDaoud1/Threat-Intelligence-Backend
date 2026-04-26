from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Security, HTTPException, status, Depends
from fastapi.security import APIKeyHeader
import redis.asyncio as aioredis
import uuid
from datetime import datetime, timezone
from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.models.organisation import Organisation
from app.services.auth_service import AuthService
from app.config import settings

# Dependency pour la session DB
async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

# Dependency pour vérifier l'API Key
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)


async def invalidate_api_key_cache() -> None:
    r = aioredis.from_url(settings.REDIS_URL)
    cursor = 0
    while True:
        cursor, keys = await r.scan(cursor=cursor, match="apikey:*", count=100)
        if keys:
            await r.delete(*keys)
        if cursor == 0:
            break

async def verify_api_key(
    api_key: str = Security(api_key_header),
    db: AsyncSession = Depends(get_db),
) -> uuid.UUID:
    r = aioredis.from_url(settings.REDIS_URL)

    # Vérification en base de données + mise en cache
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(Organisation).where(
            Organisation.status == "approved",
            Organisation.api_key_revoked_at.is_(None),
        )
    )
    for org in result.scalars():
        if org.api_key_expires_at is not None and org.api_key_expires_at <= now:
            continue
        if AuthService.verify_key(api_key, org.api_key_hash, org.api_key_salt):
            org.api_key_last_used_at = now
            await db.commit()
            await r.setex(f"apikey:{api_key}", 300, str(org.id))   # cache 5 minutes
            return org.id

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or revoked API key"
    )