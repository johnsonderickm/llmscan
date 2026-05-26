import os
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL: str = os.getenv(
    "LLMSCAN_DATABASE_URL",
    "sqlite+aiosqlite:///./llmscan.db",
)

engine: AsyncEngine = create_async_engine(DATABASE_URL, echo=False)

_AsyncSessionFactory = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields a database session per request."""
    async with _AsyncSessionFactory() as session:
        yield session
