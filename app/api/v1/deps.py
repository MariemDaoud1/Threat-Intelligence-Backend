from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Security, HTTPException, status, Depends
from fastapi.security import APIKeyHeader
import redis.asyncio as aioredis
import uuid
import hashlib
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

async def verify_api_key(
    api_key: str = Security(api_key_header),
    db: AsyncSession = Depends(get_db),
) -> uuid.UUID:
    r = aioredis.from_url(settings.REDIS_URL)

    # Vérification rapide dans le cache Redis
    cached = await r.get(f"apikey:{api_key}")
    if cached:
        return uuid.UUID(cached.decode())

    # Vérification en base de données + mise en cache
    result = await db.execute(
        select(Organisation).where(Organisation.status == "approved")
    )
    for org in result.scalars():
        if AuthService.verify_key(api_key, org.api_key_hash, org.api_key_salt):
            await r.setex(f"apikey:{api_key}", 300, str(org.id))   # cache 5 minutes
            return org.id

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or revoked API key"
    )