import os
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool
from app.core.config import settings
from app.core.logging import logger

# For serverless (Vercel) and pooled Supabase connections, NullPool prevents pooler exhaustion (EMAXCONNSESSION)
is_serverless = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))

engine_kwargs = {
    "echo": False,
    "pool_pre_ping": True,
    "pool_recycle": 60,
}

if is_serverless or "sqlite" in settings.async_db_url or "pooler.supabase.com" in settings.async_db_url:
    engine_kwargs["poolclass"] = NullPool
else:
    engine_kwargs["pool_size"] = 2
    engine_kwargs["max_overflow"] = 3
    engine_kwargs["pool_timeout"] = 10

# Async Engine for FastAPI (Supabase PostgreSQL via asyncpg)
async_engine = create_async_engine(
    settings.async_db_url,
    **engine_kwargs
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)

# Synchronous Engine for Alembic migrations and CLI tasks
sync_engine = create_engine(
    settings.sync_db_url,
    pool_pre_ping=True,
    pool_recycle=60,
    poolclass=NullPool if (is_serverless or "pooler.supabase.com" in settings.sync_db_url) else None,
)


async def check_database_connection() -> bool:
    """Verifies that the database is reachable."""
    try:
        from sqlalchemy import text
        async with async_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database connection check failed: {e}")
        return False
