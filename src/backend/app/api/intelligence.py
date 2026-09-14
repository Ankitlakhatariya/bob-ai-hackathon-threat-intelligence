from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.dependencies import get_db
from app.models.indicator import Indicator, IndicatorType, IndicatorReputation
from app.schemas.intelligence import IndicatorRead, IndicatorCreate, IndicatorLookupResponse
from app.services.intelligence import ThreatIntelService

router = APIRouter()


@router.get("/indicators", response_model=List[IndicatorRead])
async def get_indicators(
    type: Optional[str] = Query(None),
    reputation: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Indicator).order_by(Indicator.last_seen.desc())
    if type:
        try:
            stmt = stmt.where(Indicator.indicator_type == IndicatorType(type.lower()))
        except ValueError:
            pass
    if reputation:
        try:
            stmt = stmt.where(Indicator.reputation == IndicatorReputation(reputation.lower()))
        except ValueError:
            pass

    stmt = stmt.offset(skip).limit(limit)
    res = await db.execute(stmt)
    return list(res.scalars().all())


@router.get("/indicators/{indicator_id}", response_model=IndicatorRead)
async def get_indicator(indicator_id: UUID, db: AsyncSession = Depends(get_db)):
    ioc = await db.get(Indicator, indicator_id)
    if not ioc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": f"Indicator {indicator_id} not found"}},
        )
    return ioc


@router.post("/indicators", response_model=IndicatorRead, status_code=status.HTTP_201_CREATED)
async def create_indicator(payload: IndicatorCreate, db: AsyncSession = Depends(get_db)):
    ioc = Indicator(
        indicator_value=payload.indicator_value,
        indicator_type=payload.indicator_type,
        threat_type=payload.threat_type,
        confidence=payload.confidence,
        reputation=payload.reputation,
        source=payload.source,
        tags=payload.tags,
    )
    db.add(ioc)
    await db.commit()
    await db.refresh(ioc)
    return ioc


@router.get("/lookup/{indicator_val:path}", response_model=IndicatorLookupResponse)
async def lookup_indicator(indicator_val: str, db: AsyncSession = Depends(get_db)):
    """Fast IOC lookup for analysts and automated enrichment."""
    ioc = await ThreatIntelService.lookup_indicator(db, indicator_val)
    matching_alerts = await ThreatIntelService.find_matching_alerts(db, indicator_val)

    if not ioc:
        return IndicatorLookupResponse(
            indicator=indicator_val,
            found=False,
            reputation=IndicatorReputation.UNKNOWN,
            confidence=0,
            tags=[],
            associated_alerts=matching_alerts,
        )

    return IndicatorLookupResponse(
        indicator=indicator_val,
        found=True,
        reputation=ioc.reputation,
        confidence=ioc.confidence,
        threat_type=ioc.threat_type,
        source=ioc.source,
        tags=ioc.tags,
        associated_alerts=matching_alerts,
    )
