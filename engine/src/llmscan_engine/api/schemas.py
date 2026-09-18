import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel

from llmscan_engine.db.models import FailureMode, ScanStatus


class ScanCreate(BaseModel):
    """Request body for POST /scans."""

    target_url: str
    api_key: str
    profile: str = "standard"
    dry_run: bool = False
    use_garak: bool = True
    model: Optional[str] = None
    endpoint_format: str = "openai"
    request_template: Optional[str] = None
    response_path: Optional[str] = None


class ScanRead(BaseModel):
    """Response body for scan endpoints."""

    id: uuid.UUID
    target_url: str
    profile: str
    started_at: datetime
    finished_at: Optional[datetime]
    risk_score: Optional[float]
    status: ScanStatus

    model_config = {"from_attributes": True}


class FindingRead(BaseModel):
    """Response body for finding endpoints."""

    id: uuid.UUID
    scan_id: uuid.UUID
    plugin_id: str
    owasp_id: str
    mitre_atlas_id: Optional[str]
    failure_mode: FailureMode
    score: float
    payload_hash: str
    response_hash: str
    evidence_path: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingEvidence(BaseModel):
    """The actual prompt/response behind a finding, pulled from evidence.ndjson."""

    finding_id: uuid.UUID
    prompt_text: str
    response_text: str
    status_code: int
    latency_ms: float
    url: str
    timestamp: str


class PluginRead(BaseModel):
    """Response body for plugin list endpoint."""

    id: str
    name: str
    version: str
    owasp_id: str
    mitre_atlas_id: Optional[str]
    severity_weight: float
    tags: List[str]


class ReportRequest(BaseModel):
    """Request body for POST /scans/{id}/report."""

    audience: str = "pentester"
    format: str = "html"


class ReportResponse(BaseModel):
    """Response body for report generation endpoint."""

    scan_id: uuid.UUID
    audience: str
    format: str
    path: str
    message: str
