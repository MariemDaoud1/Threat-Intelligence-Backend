import os
import json
from pydantic_settings import BaseSettings, SettingsConfigDict


def _to_localhost_on_windows(url: str, docker_host: str) -> str:
    # On Windows local runs, Docker service DNS names (db/redis) are not resolvable.
    if os.name == "nt" and f"@{docker_host}" in url:
        return url.replace(f"@{docker_host}", "@localhost")
    if os.name == "nt" and f"//{docker_host}" in url:
        return url.replace(f"//{docker_host}", "//localhost")
    return url

class Settings(BaseSettings):
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    API_KEY_EXPIRE_DAYS: int = 90
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    DATABASE_URL: str = "postgresql+asyncpg://user:password@localhost:5432/threatintel"
    REDIS_URL: str = "redis://localhost:6379/0"
    SECRET_KEY: str = "change-me"
    SMTP_ENABLED: bool = False
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 1025
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = "noreply@threatintel.local"
    SMTP_STARTTLS: bool = False
    SMTP_USE_SSL: bool = False
    ETH_RPC_URL: str = ""
    ETH_PRIVATE_KEY: str = ""
    ETH_CHAIN_ID: int = 11155111
    ETH_CONTRACT_ADDRESS: str = ""
    ETH_TX_TIMEOUT_SECONDS: int = 120
    OLLAMA_BASE_URL: str = "http://host.docker.internal:11434"
    OLLAMA_MODEL: str = "qwen2.5:7b"
    OLLAMA_TIMEOUT_SECONDS: float = 25.0
    CORS_ALLOW_ORIGINS: list[str] | str = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

settings = Settings()
settings.DATABASE_URL = _to_localhost_on_windows(settings.DATABASE_URL, "db")
settings.REDIS_URL = _to_localhost_on_windows(settings.REDIS_URL, "redis")

if isinstance(settings.CORS_ALLOW_ORIGINS, str):
    raw = settings.CORS_ALLOW_ORIGINS.strip()
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            settings.CORS_ALLOW_ORIGINS = [str(origin).strip() for origin in parsed if str(origin).strip()]
        else:
            settings.CORS_ALLOW_ORIGINS = [raw]
    except json.JSONDecodeError:
        settings.CORS_ALLOW_ORIGINS = [origin.strip() for origin in raw.split(",") if origin.strip()]
