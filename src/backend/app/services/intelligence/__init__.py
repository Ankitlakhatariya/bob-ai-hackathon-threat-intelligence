from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.indicator import Indicator, IndicatorReputation
from app.models.alert import Alert

from app.services.intelligence.provider import (
    AbstractThreatIntelProvider,
    ThreatIntelResult,
    ExternalThreatIntelProvider,
)
from app.services.intelligence.manager import ThreatIntelManager, intel_manager


class ThreatIntelService:
    @classmethod
    async def lookup_indicator(cls, db: AsyncSession, indicator_val: str) -> Optional[Indicator]:
        stmt = select(Indicator).where(Indicator.indicator == indicator_val)
        result = await db.execute(stmt)
        return result.scalars().first()

    @classmethod
    async def find_matching_alerts(cls, db: AsyncSession, indicator_val: str) -> List[str]:
        stmt = select(Alert.id).where(Alert.indicators.any(indicator_val))
        result = await db.execute(stmt)
        return list(result.scalars().all())


__all__ = [
    "AbstractThreatIntelProvider",
    "ThreatIntelResult",
    "ExternalThreatIntelProvider",
    "ThreatIntelManager",
    "intel_manager",
    "ThreatIntelService",
]
