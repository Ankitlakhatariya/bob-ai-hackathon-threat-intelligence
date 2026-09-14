from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import socket
from urllib.parse import urlparse
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

    @staticmethod
    def _is_safe_url(url: str) -> bool:
        """
        SSRF Protection: Validates that a URL only points to public, external infrastructure.
        Rejects RFC1918 private IPs, loopback, link-local, and cloud metadata endpoints.
        """
        try:
            parsed = urlparse(url if "://" in url else f"http://{url}")
            if parsed.scheme not in ("http", "https"):
                return False
            
            hostname = parsed.hostname
            if not hostname:
                return False
                
            # Resolve DNS
            ip_str = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(ip_str)
            
            # Reject internal/private/loopback ranges
            if ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved or ip.is_link_local or ip.is_unspecified:
                return False
                
            # Explicit block for AWS/Cloud metadata
            if ip_str == "169.254.169.254":
                return False
                
            return True
        except Exception:
            return False

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

        # SSRF Protection: Ensure we do not fetch arbitrary internal resources if this provider 
        # is configured to fetch URL indicators.
        if indicator_type == IndicatorType.URL or (indicator_type is None and "/" in indicator):
            if not self._is_safe_url(indicator):
                return ThreatIntelResult(
                    indicator=indicator,
                    indicator_type=IndicatorType.URL,
                    reputation=IndicatorReputation.UNKNOWN,
                    confidence=0,
                    source=self.name,
                    found=False,
                    tags=["blocked_ssrf_risk"],
                )

        # When integrated with an actual external HTTP endpoint, make network call here.
        # If external API returns 404 or unknown, do not fabricate results.
        return None
