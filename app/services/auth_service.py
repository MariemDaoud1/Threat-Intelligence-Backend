import base64
import hashlib
import hmac
import secrets
import string
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.config import settings


class AuthService:
    @staticmethod
    def generate_api_key() -> tuple[str, str, str]:
        """Retourne (raw_key, blake2b_hash, salt)"""
        raw = secrets.token_urlsafe(32)
        salt = secrets.token_hex(16)
        h = hashlib.blake2b(
            raw.encode(), salt=bytes.fromhex(salt)
        ).hexdigest()
        return raw, h, salt

    @staticmethod
    def verify_key(raw: str, stored_hash: str, salt: str) -> bool:
        """Vérification sécurisée (constant-time)"""
        h = hashlib.blake2b(
            raw.encode(), salt=bytes.fromhex(salt)
        ).hexdigest()
        return secrets.compare_digest(h, stored_hash)

    @staticmethod
    def generate_temp_password(length: int = 16) -> str:
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def hash_password(password: str, salt: str | None = None) -> str:
        if salt is None:
            salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            bytes.fromhex(salt),
            390000,
        )
        return f"{salt}${base64.b64encode(digest).decode()}"

    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        try:
            salt, encoded_digest = stored_hash.split("$", 1)
        except ValueError:
            return False
        expected = AuthService.hash_password(password, salt)
        return hmac.compare_digest(expected, stored_hash)


# JWT METHODS (pour Admin)
ALGORITHM = "HS256"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/admin/login")


def create_access_token(subject: str) -> str:
    """Crée un JWT pour l'admin"""
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": subject, "exp": expire, "type": "access"}
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])


def verify_jwt(token: str = Depends(oauth2_scheme)) -> str:
    """Vérifie un JWT et retourne le subject"""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )