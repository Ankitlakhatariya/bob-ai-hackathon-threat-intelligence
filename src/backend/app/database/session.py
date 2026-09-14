from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import create_engine
from app.core.config import settings
from app.core.logging import logger

# Async Engine for FastAPI (Supabase PostgreSQL via asyncpg)
async_engine = create_async_engine(
    settings.async_db_url,
    echo=False,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=300,
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
    pool_recycle=300,
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
