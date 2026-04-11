import os
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
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    DATABASE_URL: str = "postgresql+asyncpg://user:password@localhost:5432/threatintel"
    REDIS_URL: str = "redis://localhost:6379/0"
    SECRET_KEY: str = "change-me"

settings = Settings()
settings.DATABASE_URL = _to_localhost_on_windows(settings.DATABASE_URL, "db")
settings.REDIS_URL = _to_localhost_on_windows(settings.REDIS_URL, "redis")