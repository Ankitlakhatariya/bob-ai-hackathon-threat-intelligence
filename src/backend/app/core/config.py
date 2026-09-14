from typing import List, Union
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    PROJECT_NAME: str = "D2 Threat Intelligence Correlation & Alert Prioritisation Assistant"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"

    # Supabase Configuration
    SUPABASE_URL: str = "https://vxqrcffxhkvwlbastvus.supabase.co"
    SUPABASE_ANON_KEY: str = ""
    SUPABASE_SERVICE_ROLE_KEY: str = ""
    SUPABASE_DB_URL: str = "postgresql+asyncpg://postgres:Dhruv%40898689@db.vxqrcffxhkvwlbastvus.supabase.co:5432/postgres"
    DATABASE_URL_SYNC: str = "postgresql://postgres:Dhruv%40898689@db.vxqrcffxhkvwlbastvus.supabase.co:5432/postgres"

    # OpenAI Configuration
    OPENAI_API_KEY: Union[str, None] = None
    OPENAI_MODEL: str = "gpt-5.6-sol"

    # JWT Settings for Supabase Auth
    JWT_AUDIENCE: str = "authenticated"
    JWT_ISSUER: str = ""
    SUPABASE_JWT_SECRET: str = ""

    # CORS
    CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000"
    ]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return ["*"]

    @property
    def async_db_url(self) -> str:
        url = self.SUPABASE_DB_URL
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
        elif url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+asyncpg://", 1)
        return url

    @property
    def sync_db_url(self) -> str:
        if self.DATABASE_URL_SYNC:
            return self.DATABASE_URL_SYNC
        url = self.SUPABASE_DB_URL
        if url.startswith("postgresql+asyncpg://"):
            url = url.replace("postgresql+asyncpg://", "postgresql://", 1)
        return url


settings = Settings()
