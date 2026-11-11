from sqlalchemy import create_engine, inspect
from sqlmodel import SQLModel

from llmscan_engine.db.init_db import _add_missing_columns

# finding as it existed before Phase 15 (no simulated / confidence /
# decided_by_layer columns).
_OLD_FINDING = """
CREATE TABLE finding (
    id CHAR(32) NOT NULL PRIMARY KEY,
    scan_id CHAR(32) NOT NULL,
    plugin_id VARCHAR NOT NULL,
    owasp_id VARCHAR NOT NULL,
    mitre_atlas_id VARCHAR,
    failure_mode VARCHAR(20) NOT NULL,
    score FLOAT NOT NULL,
    payload_hash VARCHAR NOT NULL,
    response_hash VARCHAR NOT NULL,
    evidence_path VARCHAR,
    created_at DATETIME NOT NULL
)
"""


def _old_db():
    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        conn.exec_driver_sql(_OLD_FINDING)
        conn.exec_driver_sql(
            "INSERT INTO finding VALUES ('a', 'b', 'p', 'LLM01', NULL, "
            "'COMPLIED', 10.0, 'h', 'h', NULL, '2026-01-01 00:00:00')"
        )
    return engine


def test_adds_missing_columns_to_existing_table() -> None:
    engine = _old_db()
    with engine.begin() as conn:
        added = _add_missing_columns(conn)
        columns = {c["name"] for c in inspect(conn).get_columns("finding")}
    expected = {
        "finding.simulated",
        "finding.confidence",
        "finding.decided_by_layer",
    }
    assert expected <= set(added)
    assert {"simulated", "confidence", "decided_by_layer"} <= columns


def test_existing_rows_get_defaults() -> None:
    engine = _old_db()
    with engine.begin() as conn:
        _add_missing_columns(conn)
        row = conn.exec_driver_sql(
            "SELECT simulated, confidence, decided_by_layer FROM finding"
        ).one()
    assert row == (0, None, None)


def test_is_idempotent_and_skips_missing_tables() -> None:
    engine = _old_db()
    with engine.begin() as conn:
        _add_missing_columns(conn)
        assert _add_missing_columns(conn) == []


def test_fresh_schema_needs_nothing() -> None:
    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        SQLModel.metadata.create_all(conn)
        assert _add_missing_columns(conn) == []
