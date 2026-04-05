from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import sessionmaker
from app.config import settings

# Async engine → used by FastAPI routes
engine = create_async_engine(settings.DATABASE_URL, echo=True)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# Sync engine → used by Alembic for migrations
sync_engine = create_engine(settings.DATABASE_URL.replace("+asyncpg", ""), pool_size=10, echo=True)
SyncSessionLocal = sessionmaker(sync_engine, autocommit=False, autoflush=False)