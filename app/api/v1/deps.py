from collections.abc import AsyncGenerator
from datetime import datetime, timezone
import uuid

import redis.asyncio as aioredis
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.db.session import AsyncSessionLocal
from app.models.contributor_user import ContributorUser
from app.models.organisation import Organisation
from app.services.auth_service import AuthService, decode_access_token, oauth2_scheme


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


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
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(Organisation).where(
            Organisation.status == "approved",
            Organisation.api_key_revoked_at.is_(None),
        )
    )
    for org in result.scalars():
        if not org.api_key_hash or not org.api_key_salt:
            continue
        if org.api_key_expires_at is not None and org.api_key_expires_at <= now:
            continue
        try:
            key_is_valid = AuthService.verify_key(api_key, org.api_key_hash, org.api_key_salt)
        except (ValueError, TypeError):
            continue
        if key_is_valid:
            org.api_key_last_used_at = now
            await db.commit()
            try:
                await r.setex(f"apikey:{api_key}", 300, str(org.id))
            except Exception:
                pass
            return org.id
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked API key")


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> ContributorUser:
    try:
        payload = decode_access_token(token)
        user_id = uuid.UUID(payload["sub"])
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    result = await db.execute(
        select(ContributorUser)
        .options(selectinload(ContributorUser.organisation))
        .where(ContributorUser.id == user_id)
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


async def require_admin(user: ContributorUser = Depends(get_current_user)) -> ContributorUser:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator access required")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator account is inactive")
    return user


async def require_contributor(user: ContributorUser = Depends(get_current_user)) -> ContributorUser:
    if user.role != "contributor":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Contributor access required")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Contributor account is inactive")
    if user.org_id is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Contributor organisation is missing")
    return user
