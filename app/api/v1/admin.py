from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
import uuid

from app.api.v1.deps import get_db
from app.services.auth_service import create_access_token, verify_jwt
from app.models.organisation import Organisation
from app.rate_limiter import limiter

router = APIRouter(prefix="/admin", tags=["Admin"])


#  Modèle pour le login  
class AdminLogin(BaseModel):
    username: str
    password: str


#  LOGIN  
@router.post("/login")
@limiter.limit("5/minute")
async def admin_login(request: Request, credentials: AdminLogin):
    """Login admin avec body JSON"""
    if credentials.username != "admin" or credentials.password != "admin123":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    token = create_access_token(subject="admin")
    return {"access_token": token, "token_type": "bearer"}

#  AUTRES ROUTES (protégées par JWT)  
@router.get("/requests")
async def list_pending_requests(
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_jwt)
):
    try:
        result = await db.execute(select(Organisation).where(Organisation.status == "pending"))
        pending_orgs = result.scalars().all()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable. Check DATABASE_URL and database host."
        )
    data = [
        {
            "id": str(org.id),
            "name": org.name,
            "siret": org.siret,
            "email": org.email,
            "status": org.status,
        }
        for org in pending_orgs
    ]
    return {"data": data, "error": None}


@router.post("/approve/{org_id}")
async def approve_organisation(
    org_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_jwt)
):
    result = await db.execute(
        update(Organisation).where(Organisation.id == org_id).values(status="approved")
    )
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Organisation not found")
    return {"message": "Organisation approved successfully"}


@router.post("/revoke/{org_id}")
async def revoke_organisation(
    org_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(verify_jwt)
):
    result = await db.execute(
        update(Organisation).where(Organisation.id == org_id).values(status="revoked")
    )
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Organisation not found")
    return {"message": "Organisation revoked successfully"}