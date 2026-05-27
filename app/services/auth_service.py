import base64
import hashlib
import hmac
import secrets
import string
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from app.config import settings


class AuthService:
    @staticmethod
    def generate_api_key() -> tuple[str, str, str]:
        raw = secrets.token_urlsafe(32)
        salt = secrets.token_hex(16)
        digest = hashlib.blake2b(raw.encode(), salt=bytes.fromhex(salt)).hexdigest()
        return raw, digest, salt

    @staticmethod
    def verify_key(raw: str, stored_hash: str, salt: str) -> bool:
        digest = hashlib.blake2b(raw.encode(), salt=bytes.fromhex(salt)).hexdigest()
        return secrets.compare_digest(digest, stored_hash)

    @staticmethod
    def generate_temp_password(length: int = 16) -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def hash_password(password: str, salt: str | None = None) -> str:
        if salt is None:
            salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 390000)
        return f"{salt}${base64.b64encode(digest).decode()}"

    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        try:
            salt, _ = stored_hash.split("$", 1)
        except ValueError:
            return False
        expected = AuthService.hash_password(password, salt)
        return hmac.compare_digest(expected, stored_hash)


ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def create_access_token(subject: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": subject, "role": role, "type": "access", "exp": expire}
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])


def verify_jwt(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        subject = payload.get("sub")
        role = payload.get("role")
        if not subject or not role:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return payload
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
