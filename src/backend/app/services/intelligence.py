from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.indicator import Indicator, IndicatorReputation
from app.models.alert import Alert


class ThreatIntelService:
    @classmethod
    async def lookup_indicator(cls, db: AsyncSession, indicator_val: str) -> Optional[Indicator]:
        stmt = select(Indicator).where(Indicator.indicator_value == indicator_val)
        result = await db.execute(stmt)
        return result.scalars().first()

    @classmethod
    async def find_matching_alerts(cls, db: AsyncSession, indicator_val: str) -> List[str]:
        # Alerts containing indicator in their indicators array
        stmt = select(Alert.id).where(Alert.indicators.any(indicator_val))
        result = await db.execute(stmt)
        return list(result.scalars().all())
