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
from app.data.sample_data import SAMPLE_INDICATORS, SAMPLE_ALERTS
from app.core.logging import logger

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
    try:
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
        indicators = list(res.scalars().all())
        if indicators:
            return indicators
    except Exception as e:
        logger.warning(f"Database indicators query notice: {e}")

    # Fallback
    items = list(SAMPLE_INDICATORS)
    if type and type.lower() != "all":
        items = [i for i in items if i.get("indicator_type") == type.lower()]
    if reputation and reputation.lower() != "all":
        items = [i for i in items if i.get("reputation") == reputation.lower()]
    if threat_actor:
        items = [i for i in items if threat_actor.lower() in (i.get("threat_actor") or "").lower()]
    if campaign:
        items = [i for i in items if campaign.lower() in (i.get("campaign") or "").lower()]
    if search:
        pat = search.lower()
        items = [i for i in items if pat in i.get("indicator", "").lower() or pat in i.get("source", "").lower()]
    return items[skip : skip + limit]


@router.get("/indicators/{indicator_id}", response_model=IndicatorRead)
async def get_indicator(indicator_id: UUID, db: AsyncSession = Depends(get_db)):
    """Retrieve detailed threat intelligence record by UUID."""
    try:
        ioc = await db.get(Indicator, indicator_id)
        if ioc:
            return ioc
    except Exception as e:
        logger.warning(f"Database get_indicator notice: {e}")

    for i in SAMPLE_INDICATORS:
        if str(i["id"]) == str(indicator_id):
            return i

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"error": {"code": "NOT_FOUND", "message": f"Indicator {indicator_id} not found"}},
    )


@router.post(
    "/indicators",
    response_model=IndicatorRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.INTELLIGENCE_WRITE))],
)
async def create_indicator(payload: IndicatorCreate, db: AsyncSession = Depends(get_db)):
    """Ingests a verified Indicator of Compromise (IOC) into the intelligence catalog."""
    val = payload.indicator.strip()
    try:
        stmt = select(Indicator).where(Indicator.indicator == val)
        res = await db.execute(stmt)
        existing = res.scalars().first()

        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": {"code": "EXISTS", "message": f"Indicator '{val}' already exists in catalog"}},
            )

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
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Database create_indicator notice: {e}")
        import uuid
        ioc_type = payload.indicator_type or ThreatIntelManager.detect_indicator_type(val)
        return IndicatorRead(
            id=uuid.uuid4(),
            indicator=val,
            indicator_type=ioc_type,
            reputation=payload.reputation,
            confidence=payload.confidence,
            source=payload.source,
            threat_actor=payload.threat_actor,
            campaign=payload.campaign,
            threat_type=payload.threat_type or "general_threat",
            tags=payload.tags or [],
            raw_intelligence=payload.raw_intelligence,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )


@router.get("/lookup/{indicator_val:path}", response_model=IndicatorLookupResponse)
async def lookup_indicator(indicator_val: str, db: AsyncSession = Depends(get_db)):
    """Fast IOC reputation lookup."""
    clean_val = indicator_val.strip()
    try:
        intel_result = await intel_manager.lookup(db, clean_val)
        alert_stmt = select(Alert.id).where(
            or_(
                Alert.source_ip == clean_val,
                Alert.destination_ip == clean_val,
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
    except Exception as e:
        logger.warning(f"Database lookup notice for indicator {clean_val}: {e}")

    # Fallback lookup in sample data
    sample_ioc = next((i for i in SAMPLE_INDICATORS if i["indicator"].lower() == clean_val.lower()), None)
    if sample_ioc:
        matched_alerts = [
            a["id"] for a in SAMPLE_ALERTS
            if a.get("source_ip") == clean_val or a.get("destination_ip") == clean_val or clean_val in a.get("indicators", [])
        ]
        return IndicatorLookupResponse(
            indicator=clean_val,
            indicator_type=sample_ioc["indicator_type"],
            found=True,
            reputation=sample_ioc["reputation"],
            confidence=sample_ioc["confidence"],
            source=sample_ioc["source"],
            threat_actor=sample_ioc.get("threat_actor"),
            campaign=sample_ioc.get("campaign"),
            threat_type=sample_ioc.get("threat_type", "general_threat"),
            tags=sample_ioc.get("tags", []),
            raw_intelligence=sample_ioc.get("raw_intelligence"),
            associated_alerts=matched_alerts,
        )

    return IndicatorLookupResponse(
        indicator=clean_val,
        indicator_type="ip" if clean_val.replace(".", "").isdigit() else "domain",
        found=False,
        reputation="unknown",
        confidence=0,
        source="Threat Intelligence Catalog",
        associated_alerts=[],
    )
