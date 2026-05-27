from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import get_db
from app.models.contributor_user import ContributorUser
from app.rate_limiter import limiter
from app.services.auth_service import AuthService, create_access_token


router = APIRouter(prefix="/auth", tags=["Auth"])


class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/login")
@limiter.limit("10/minute")
async def admin_login(
    request: Request,
    payload: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ContributorUser).where(
            ContributorUser.email == payload.email,
            ContributorUser.role == "admin",
        )
    )
    user = result.scalar_one_or_none()
    if user is None or not AuthService.verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin account is inactive")

    token = create_access_token(subject=str(user.id), role="admin")
    return {"access_token": token, "token_type": "bearer"}
