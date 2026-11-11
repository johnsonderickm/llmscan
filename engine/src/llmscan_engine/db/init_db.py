from sqlalchemy import inspect
from sqlalchemy.engine import Connection
from sqlmodel import SQLModel

from . import models as _models  # noqa: F401 — registers table metadata
from .database import engine


def _default_sql(column) -> str:
    """Return a ``DEFAULT …`` clause for a NOT NULL column being added, or ""."""
    default = getattr(column.default, "arg", None)
    if isinstance(default, bool):
        return f" DEFAULT {int(default)}"
    if isinstance(default, (int, float)):
        return f" DEFAULT {default}"
    if isinstance(default, str):
        escaped = default.replace("'", "''")
        return f" DEFAULT '{escaped}'"
    return ""


def _add_missing_columns(conn: Connection) -> list[str]:
    """Add model columns that are missing from existing tables.

    ``create_all`` creates missing tables but never alters existing ones, so
    a database created before a column was added (e.g. ``finding.simulated``
    in Phase 15 A, ``finding.confidence`` in Phase 15 B) would fail on the
    first insert. Only additive changes are handled: nullable columns, or
    NOT NULL columns with a scalar Python default. Returns the columns added.
    """
    inspector = inspect(conn)
    existing_tables = set(inspector.get_table_names())
    added: list[str] = []
    for table in SQLModel.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue
        present = {c["name"] for c in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in present:
                continue
            col_type = column.type.compile(dialect=conn.dialect)
            default = _default_sql(column)
            not_null = "" if column.nullable or not default else " NOT NULL"
            conn.exec_driver_sql(
                f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" '
                f"{col_type}{not_null}{default}"
            )
            added.append(f"{table.name}.{column.name}")
    return added


async def init_db() -> None:
    """Create missing tables, and add missing columns to existing ones."""
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
        await conn.run_sync(_add_missing_columns)
