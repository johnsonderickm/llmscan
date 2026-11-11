import uuid
from typing import List, Optional

from pydantic import BaseModel, Field

from llmscan_engine.db.models import FailureMode


class PluginMetadata(BaseModel):
    """Static descriptor returned by AttackPlugin.metadata()."""

    id: str
    name: str
    version: str
    owasp_id: str
    mitre_atlas_id: Optional[str] = None
    severity_weight: float = Field(ge=0.0, le=10.0)
    tags: List[str] = Field(default_factory=list)


class Payload(BaseModel):
    """A single attack payload ready to be dispatched to the target LLM."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plugin_id: str
    owasp_id: str
    template_id: str
    content: str
    mutation_index: int = 0
    # Per-payload canary token planted in the attack (or in the system prompt
    # for LLM07). Its presence in the response is a deterministic verdict.
    canary: Optional[str] = None
    # Overrides the target profile's system prompt for this one request
    # (LLM07 plants a canary-bearing system prompt this way).
    system_prompt: Optional[str] = None


class ClassifierResult(BaseModel):
    """Classification of one LLM response to an attack payload."""

    failure_mode: FailureMode
    score: float = Field(ge=0.0, le=10.0)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_snippet: str
    simulated: bool = False
    # True when the verdict comes from a deterministic signal (a canary token
    # found or provably absent) rather than a heuristic. The classifier treats
    # a deterministic Layer 1 verdict as authoritative and skips other layers.
    deterministic: bool = False
