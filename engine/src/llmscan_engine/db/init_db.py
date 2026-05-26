from sqlmodel import SQLModel

from . import models as _models  # noqa: F401 — registers table metadata
from .database import engine


async def init_db() -> None:
    """Create all database tables if they do not already exist."""
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
