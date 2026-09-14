import re
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.indicator import Indicator, IndicatorType, IndicatorReputation
from app.models.alert import Alert, AlertSeverity
from app.services.intelligence.provider import (
    AbstractThreatIntelProvider,
    ThreatIntelResult,
    ExternalThreatIntelProvider,
)
from app.core.logging import logger

IPV4_PATTERN = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class ThreatIntelManager:
    """Manages internal indicator catalog and external intelligence providers.
    Provides automated IOC classification and alert enrichment.
    """

    def __init__(self, external_providers: Optional[List[AbstractThreatIntelProvider]] = None):
        self.providers: List[AbstractThreatIntelProvider] = external_providers or [
            ExternalThreatIntelProvider()
        ]

    @classmethod
    def detect_indicator_type(cls, val: str) -> IndicatorType:
        """Classifies indicator type using strict syntax patterns."""
        v = val.strip()
        if IPV4_PATTERN.match(v):
            return IndicatorType.IP
        elif HASH_PATTERN.match(v):
            return IndicatorType.HASH
        elif URL_PATTERN.match(v):
            return IndicatorType.URL
        elif EMAIL_PATTERN.match(v):
            return IndicatorType.EMAIL
        elif "." in v and "/" not in v and not v.endswith(".exe"):
            return IndicatorType.DOMAIN
        else:
            return IndicatorType.MALWARE

    async def lookup(self, db: AsyncSession, indicator_val: str) -> ThreatIntelResult:
        """Unified threat intelligence lookup.
        Checks internal database first, then external providers.
        Returns UNKNOWN reputation if not found or unconfigured.
        """
        val = indicator_val.strip()
        detected_type = self.detect_indicator_type(val)

        # 1. Search internal verified database
        stmt = select(Indicator).where(Indicator.indicator == val)
        res = await db.execute(stmt)
        record = res.scalars().first()

        if record:
            return ThreatIntelResult(
                indicator=record.indicator,
                indicator_type=record.indicator_type,
                reputation=record.reputation,
                confidence=record.confidence,
                source=record.source,
                found=True,
                threat_actor=record.threat_actor,
                campaign=record.campaign,
                threat_type=record.threat_type,
                tags=record.tags or [],
                raw_intelligence=record.raw_intelligence,
                first_seen=record.first_seen,
                last_seen=record.last_seen,
            )

        # 2. Query configured external providers
        for provider in self.providers:
            if provider.is_configured:
                try:
                    result = await provider.lookup(val, detected_type)
                    if result and result.found:
                        return result
                except Exception as e:
                    logger.warning(f"Error querying threat provider {provider.name}: {e}")

        # 3. If unconfigured or not found, return UNKNOWN (never fabricate!)
        return ThreatIntelResult(
            indicator=val,
            indicator_type=detected_type,
            reputation=IndicatorReputation.UNKNOWN,
            confidence=0,
            source="none",
            found=False,
            tags=[],
        )

    async def enrich_alert(self, db: AsyncSession, alert: Alert) -> List[ThreatIntelResult]:
        """Enriches an alert by cross-referencing all its indicators with threat intelligence.
        Elevates alert risk score and severity if malicious indicators are identified.
        """
        if not alert.indicators:
            return []

        matched_intel: List[ThreatIntelResult] = []
        has_malicious = False

        for ioc in alert.indicators:
            intel = await self.lookup(db, ioc)
            if intel.found:
                matched_intel.append(intel)
                if intel.reputation == IndicatorReputation.MALICIOUS:
                    has_malicious = True

        if matched_intel:
            # Attach intelligence to metadata_info
            current_meta = alert.metadata_info or {}
            current_meta["threat_intelligence"] = [
                {
                    "indicator": item.indicator,
                    "reputation": item.reputation.value,
                    "confidence": item.confidence,
                    "source": item.source,
                    "threat_actor": item.threat_actor,
                    "campaign": item.campaign,
                    "tags": item.tags,
                }
                for item in matched_intel
            ]
            alert.metadata_info = current_meta

            # Elevate risk if high-confidence malicious IOC detected
            if has_malicious:
                alert.risk_score = min(100, alert.risk_score + 20)
                if alert.severity in [AlertSeverity.LOW, AlertSeverity.MEDIUM]:
                    alert.severity = AlertSeverity.HIGH

        return matched_intel


intel_manager = ThreatIntelManager()
