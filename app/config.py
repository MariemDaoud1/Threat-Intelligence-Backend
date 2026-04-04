from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    DATABASE_URL: str = "postgresql+asyncpg://user:password@db/threatintel"
    REDIS_URL: str = "redis://redis:6379/0"
    SECRET_KEY: str = "change-me"

settings = Settings()