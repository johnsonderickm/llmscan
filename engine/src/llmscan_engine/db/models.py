import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from sqlalchemy import Column
from sqlalchemy.types import JSON
from sqlmodel import Field, Relationship, SQLModel


class ScanStatus(str, Enum):
    pending = "pending"
    running = "running"
    complete = "complete"
    failed = "failed"


class FailureMode(str, Enum):
    COMPLIED = "COMPLIED"
    PARTIAL = "PARTIAL"
    PII_LEAKED = "PII_LEAKED"
    HALLUCINATED_REFUSAL = "HALLUCINATED_REFUSAL"
    REFUSED = "REFUSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Scan(SQLModel, table=True):
    """A single penetration test run against a target LLM endpoint."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    target_url: str
    profile: str
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    finished_at: Optional[datetime] = None
    risk_score: Optional[float] = None
    status: ScanStatus = Field(default=ScanStatus.pending)

    findings: List["Finding"] = Relationship(back_populates="scan")
    events: List["ScanEvent"] = Relationship(back_populates="scan")


class Finding(SQLModel, table=True):
    """A single vulnerability finding produced by an attack plugin."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    scan_id: uuid.UUID = Field(foreign_key="scan.id", index=True)
    plugin_id: str
    owasp_id: str
    mitre_atlas_id: Optional[str] = None
    failure_mode: FailureMode
    score: float = Field(ge=0.0, le=10.0)
    payload_hash: str
    response_hash: str
    evidence_path: Optional[str] = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    scan: Optional[Scan] = Relationship(back_populates="findings")


class Plugin(SQLModel, table=True):
    """Registry entry for a loaded attack plugin."""

    id: str = Field(primary_key=True)
    name: str
    version: str
    owasp_id: str
    severity_weight: float = Field(ge=0.0, le=10.0)
    enabled: bool = Field(default=True)
    tags: Optional[List[str]] = Field(default=None, sa_column=Column(JSON))


class ScanEvent(SQLModel, table=True):
    """Timestamped event emitted during a scan for the live WebSocket feed."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    scan_id: uuid.UUID = Field(foreign_key="scan.id", index=True)
    event_type: str
    message: str
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    scan: Optional[Scan] = Relationship(back_populates="events")
