from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone
from app.models.indicator import IndicatorType, IndicatorReputation


@dataclass
class ThreatIntelResult:
    indicator: str
    indicator_type: IndicatorType
    reputation: IndicatorReputation
    confidence: int  # 0-100
    source: str
    found: bool = True
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    threat_type: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    raw_intelligence: Optional[Dict[str, Any]] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class AbstractThreatIntelProvider(ABC):
    """Abstract interface for threat intelligence providers.
    Allows seamlessly plugging in new feeds (e.g., AlienVault OTX, VirusTotal, MISP, AbuseIPDB)
    without modifying core application logic.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider identifier."""
        pass

    @property
    @abstractmethod
    def is_configured(self) -> bool:
        """Indicates whether provider credentials/services are available."""
        pass

    @abstractmethod
    async def lookup(
        self, indicator: str, indicator_type: Optional[IndicatorType] = None
    ) -> Optional[ThreatIntelResult]:
        """Performs indicator reputation lookup.
        Must return None or reputation='unknown' if unconfigured or indicator is not found.
        MUST NEVER fabricate or guess threat intelligence.
        """
        pass


class ExternalThreatIntelProvider(AbstractThreatIntelProvider):
    """Generic client for external threat intelligence providers (e.g., commercial or open-source feeds).
    Strictly avoids fabricating intelligence if unconfigured or indicator is unknown.
    """

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None):
        self.api_key = api_key
        self.base_url = base_url

    @property
    def name(self) -> str:
        return "External Feed Provider"

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self.base_url)

    async def lookup(
        self, indicator: str, indicator_type: Optional[IndicatorType] = None
    ) -> Optional[ThreatIntelResult]:
        if not self.is_configured:
            # When unconfigured, strictly return unknown rather than guessing
            return ThreatIntelResult(
                indicator=indicator,
                indicator_type=indicator_type or IndicatorType.IP,
                reputation=IndicatorReputation.UNKNOWN,
                confidence=0,
                source=self.name,
                found=False,
                tags=["unconfigured_provider"],
            )

        # When integrated with an actual external HTTP endpoint, make network call here.
        # If external API returns 404 or unknown, do not fabricate results.
        return None
