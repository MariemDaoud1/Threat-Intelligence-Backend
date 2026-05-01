from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import uuid
from sqlalchemy.exc import SQLAlchemyError

from app.db.session import AsyncSessionLocal
from app.models.organisation import Organisation, OrgStatus
from app.schemas.organisation import OrgRegisterRequest, OrgRead

router = APIRouter(prefix="/register", tags=["Registration"])


async def get_db() -> AsyncSession:
    """Dependency to get database session"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


@router.post("", status_code=status.HTTP_201_CREATED, response_model=dict)
async def register_organisation(
    data: OrgRegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new organisation.
    Initial status: pending
    """
    
    try:
        # Check for duplicate SIRET
        result = await db.execute(
            select(Organisation).where(Organisation.siret == data.siret)
        )
        if result.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="SIRET already registered."
            )

        # Check for duplicate email
        result = await db.execute(
            select(Organisation).where(Organisation.email == data.email)
        )
        if result.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered."
            )

        # Create new organisation
        org = Organisation(
            id=uuid.uuid4(),
            name=data.name,
            siret=data.siret,
            email=data.email,
            website=data.website,
            description=data.description,
            country=data.country,
            status=OrgStatus.pending,
            trust_score=0
        )

        db.add(org)
        await db.commit()
        await db.refresh(org)
    except SQLAlchemyError:
        # Likely database unavailable or schema mismatch (migrations not applied).
        # Return 503 with actionable guidance rather than leaking internals.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Database error while registering organisation. "
                "Ensure the database is reachable and migrations have been applied (alembic upgrade head)."
            ),
        )
    
    return {
        "success": True,
        "id": str(org.id),
        "message": "Registration request received. An administrator will review your request."
    }
