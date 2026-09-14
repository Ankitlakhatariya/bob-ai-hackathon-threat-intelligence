from typing import List, Optional
from uuid import UUID
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from app.core.dependencies import get_db, require_permission, get_current_user
from app.core.permissions import Permission
from app.models.indicator import Indicator, IndicatorType, IndicatorReputation
from app.models.alert import Alert
from app.schemas.intelligence import IndicatorRead, IndicatorCreate, IndicatorLookupResponse
from app.services.intelligence import intel_manager, ThreatIntelManager

router = APIRouter()


@router.get("/indicators", response_model=List[IndicatorRead])
async def get_indicators(
    type: Optional[str] = Query(None, description="ip, domain, url, hash, email, malware"),
    reputation: Optional[str] = Query(None, description="malicious, suspicious, benign, unknown"),
    threat_actor: Optional[str] = Query(None, description="Filter by threat actor attribution"),
    campaign: Optional[str] = Query(None, description="Filter by campaign"),
    search: Optional[str] = Query(None, description="Search indicator or tags"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """List threat intelligence indicators with multi-field filtering and pagination."""
    stmt = select(Indicator).order_by(Indicator.last_seen.desc())

    if type and type.lower() != "all":
        try:
            stmt = stmt.where(Indicator.indicator_type == IndicatorType(type.lower()))
        except ValueError:
            pass

    if reputation and reputation.lower() != "all":
        try:
            stmt = stmt.where(Indicator.reputation == IndicatorReputation(reputation.lower()))
        except ValueError:
            pass

    if threat_actor:
        stmt = stmt.where(Indicator.threat_actor.ilike(f"%{threat_actor}%"))

    if campaign:
        stmt = stmt.where(Indicator.campaign.ilike(f"%{campaign}%"))

    if search:
        search_pat = f"%{search}%"
        stmt = stmt.where(
            or_(
                Indicator.indicator.ilike(search_pat),
                Indicator.source.ilike(search_pat),
                Indicator.threat_type.ilike(search_pat),
            )
        )

    stmt = stmt.offset(skip).limit(limit)
    res = await db.execute(stmt)
    return list(res.scalars().all())


@router.get("/indicators/{indicator_id}", response_model=IndicatorRead)
async def get_indicator(indicator_id: UUID, db: AsyncSession = Depends(get_db)):
    """Retrieve detailed threat intelligence record by UUID."""
    ioc = await db.get(Indicator, indicator_id)
    if not ioc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": f"Indicator {indicator_id} not found"}},
        )
    return ioc


@router.post(
    "/indicators",
    response_model=IndicatorRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.INTELLIGENCE_WRITE))],
)
async def create_indicator(payload: IndicatorCreate, db: AsyncSession = Depends(get_db)):
    """Ingests a verified Indicator of Compromise (IOC) into the intelligence catalog."""
    val = payload.indicator.strip()
    stmt = select(Indicator).where(Indicator.indicator == val)
    res = await db.execute(stmt)
    existing = res.scalars().first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"code": "EXISTS", "message": f"Indicator '{val}' already exists in catalog"}},
        )

    # Auto-detect type if not provided
    ioc_type = payload.indicator_type or ThreatIntelManager.detect_indicator_type(val)

    ioc = Indicator(
        indicator=val,
        indicator_type=ioc_type,
        reputation=payload.reputation,
        confidence=payload.confidence,
        source=payload.source,
        threat_actor=payload.threat_actor,
        campaign=payload.campaign,
        threat_type=payload.threat_type or "general_threat",
        tags=payload.tags,
        raw_intelligence=payload.raw_intelligence,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    db.add(ioc)
    await db.commit()
    await db.refresh(ioc)
    return ioc


@router.get("/lookup/{indicator_val:path}", response_model=IndicatorLookupResponse)
async def lookup_indicator(indicator_val: str, db: AsyncSession = Depends(get_db)):
    """Fast IOC reputation lookup.
    Queries verified internal catalog first, then configured external feeds.
    Strictly returns 'unknown' if not found — NEVER fabricates intelligence.
    """
    clean_val = indicator_val.strip()
    intel_result = await intel_manager.lookup(db, clean_val)

    # Search for associated alerts in database containing this indicator
    alert_stmt = select(Alert.id).where(
        or_(
            Alert.source_ip == clean_val,
            Alert.destination_ip == clean_val,
            Alert.indicators.any(clean_val),
        )
    )
    alerts_res = await db.execute(alert_stmt)
    associated_alerts = list(alerts_res.scalars().all())

    return IndicatorLookupResponse(
        indicator=clean_val,
        indicator_type=intel_result.indicator_type,
        found=intel_result.found,
        reputation=intel_result.reputation,
        confidence=intel_result.confidence,
        source=intel_result.source,
        threat_actor=intel_result.threat_actor,
        campaign=intel_result.campaign,
        threat_type=intel_result.threat_type,
        tags=intel_result.tags,
        raw_intelligence=intel_result.raw_intelligence,
        associated_alerts=associated_alerts,
    )
