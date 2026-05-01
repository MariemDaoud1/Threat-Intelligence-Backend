from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import uuid

from app.api.v1.deps import get_db
from app.models.contributor_user import ContributorUser
from app.services.auth_service import AuthService, create_access_token, decode_access_token
from app.schemas.assets import ContributorUserRead
from fastapi.security import OAuth2PasswordBearer

router = APIRouter(prefix="/contributor", tags=["Contributors"])

oauth2_contrib = OAuth2PasswordBearer(tokenUrl="/api/v1/contributor/login")


class ContributorLogin(BaseModel):
    email: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


async def get_current_contributor(
    token: str = Depends(oauth2_contrib), db: AsyncSession = Depends(get_db)
) -> ContributorUser:
    try:
        payload = decode_access_token(token)
        sub = payload.get("sub")
        if sub is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        contrib_id = uuid.UUID(sub)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    result = await db.execute(select(ContributorUser).where(ContributorUser.id == contrib_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Contributor not found")
    return user


@router.post("/login")
async def login(contrib: ContributorLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ContributorUser).where(ContributorUser.email == contrib.email))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not AuthService.verify_password(contrib.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_access_token(subject=str(user.id))
    return {"access_token": token, "token_type": "bearer", "must_change_password": user.must_change_password}


@router.post("/change-password")
async def change_password(
    payload: ChangePasswordRequest,
    user: ContributorUser = Depends(get_current_contributor),
    db: AsyncSession = Depends(get_db),
):
    # Allow change even if must_change_password is True
    if not AuthService.verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password incorrect")

    user.hashed_password = AuthService.hash_password(payload.new_password)
    user.must_change_password = False
    await db.commit()
    return {"message": "Password changed successfully"}


@router.get("/me")
async def me(user: ContributorUser = Depends(get_current_contributor)):
    return {"data": ContributorUserRead.model_validate(user), "error": None}
