from abc import ABC, abstractmethod
from typing import AsyncIterator, Literal

from llmscan_engine.core.connector import TargetProfile
from llmscan_engine.plugins.schemas import ClassifierResult, Payload, PluginMetadata


class AttackPlugin(ABC):
    """Abstract base class every LLMScan attack plugin must implement."""

    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Return static metadata describing this plugin."""

    @abstractmethod
    async def payload_generator(
        self, profile: TargetProfile
    ) -> AsyncIterator[Payload]:
        """Yield attack payloads tailored to the fingerprinted target profile."""

    @abstractmethod
    def response_classifier(
        self, payload: Payload, response: str
    ) -> ClassifierResult:
        """Classify a single LLM response and return a ClassifierResult."""

    @abstractmethod
    def remediation(
        self, audience: Literal["pentester", "manager", "cxo"]
    ) -> str:
        """Return audience-appropriate remediation guidance."""
