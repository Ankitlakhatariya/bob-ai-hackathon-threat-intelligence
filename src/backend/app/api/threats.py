from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from app.core.dependencies import get_db, require_permission, get_current_user
from app.core.permissions import Permission
from app.models.threat import Threat, ThreatSeverity, ThreatStatus
from app.models.alert import Alert
from app.models.mitre import MitreTechnique
from app.schemas.threat import ThreatRead, ThreatCreate, ThreatUpdate, ThreatTimelineEvent
from app.schemas.alert import AlertRead
from app.schemas.correlation import CorrelationResult
from app.schemas.mitre import MitreTechniqueRead
from app.services.correlation import CorrelationEngine
from app.services.threat_scoring import ThreatScoringEngine

router = APIRouter()


@router.get("", response_model=List[ThreatRead])
async def get_threats(
    status: Optional[str] = Query(None, description="active, investigating, resolved"),
    severity: Optional[str] = Query(None, description="critical, high, medium, low"),
    search: Optional[str] = Query(None, description="Search ID, title, or summary"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves correlated threats/incidents matching frontend incident format."""
    stmt = select(Threat).order_by(Threat.opened_at.desc())

    if status and status != "all":
        try:
            stat_enum = ThreatStatus(status.lower())
            stmt = stmt.where(Threat.status == stat_enum)
        except ValueError:
            pass

    if severity and severity != "all":
        try:
            sev_enum = ThreatSeverity(severity.lower())
            stmt = stmt.where(Threat.severity == sev_enum)
        except ValueError:
            pass

    if search:
        search_pattern = f"%{search}%"
        stmt = stmt.where(
            or_(
                Threat.id.ilike(search_pattern),
                Threat.title.ilike(search_pattern),
                Threat.summary.ilike(search_pattern),
            )
        )

    stmt = stmt.offset(skip).limit(limit)
    res = await db.execute(stmt)
    threats = list(res.scalars().all())

    for t in threats:
        if not hasattr(t, "updated_at") or t.updated_at is None:
            t.updated_at = getattr(t, "updated_at_field", t.opened_at)

    return threats


@router.get("/{threat_id}", response_model=ThreatRead)
async def get_threat(threat_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieves a single threat/incident by ID."""
    threat = await db.get(Threat, threat_id)
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "THREAT_NOT_FOUND", "message": f"Threat {threat_id} not found"}},
        )
    if not hasattr(threat, "updated_at") or threat.updated_at is None:
        threat.updated_at = getattr(threat, "updated_at_field", threat.opened_at)
    return threat


@router.get("/{threat_id}/alerts", response_model=List[AlertRead])
async def get_threat_alerts(threat_id: str, db: AsyncSession = Depends(get_db)):
    """Returns all alerts folded into this threat campaign."""
    threat = await db.get(Threat, threat_id)
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "THREAT_NOT_FOUND", "message": f"Threat {threat_id} not found"}},
        )

    stmt = select(Alert).where(
        or_(
            Alert.related_threat_id == threat_id,
            Alert.id.in_(threat.alert_ids or ["dummy-nonexistent"])
        )
    ).order_by(Alert.timestamp.asc())
    res = await db.execute(stmt)
    return list(res.scalars().all())


@router.get("/{threat_id}/timeline", response_model=List[ThreatTimelineEvent])
async def get_threat_timeline(threat_id: str, db: AsyncSession = Depends(get_db)):
    """Builds a chronological timeline of correlation and escalation events for this threat."""
    threat = await db.get(Threat, threat_id)
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "THREAT_NOT_FOUND", "message": f"Threat {threat_id} not found"}},
        )

    events = [
        ThreatTimelineEvent(time=threat.opened_at, label="Incident opened — alerts began correlating", tone="primary")
    ]

    alerts_stmt = select(Alert).where(Alert.related_threat_id == threat_id).order_by(Alert.timestamp.asc())
    alerts_res = await db.execute(alerts_stmt)
    for a in alerts_res.scalars().all():
        events.append(
            ThreatTimelineEvent(time=a.timestamp, label=f"Alert {a.id} folded into the incident ({a.title})", tone="accent")
        )

    updated_time = getattr(threat, "updated_at_field", threat.opened_at)
    events.append(
        ThreatTimelineEvent(time=updated_time, label="Last correlation activity", tone="neutral")
    )
    events.sort(key=lambda x: x.time)
    return events


@router.get("/{threat_id}/mitre", response_model=List[MitreTechniqueRead])
async def get_threat_mitre_techniques(threat_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieves all MITRE ATT&CK techniques mapped to this threat."""
    threat = await db.get(Threat, threat_id)
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "THREAT_NOT_FOUND", "message": f"Threat {threat_id} not found"}},
        )

    if not threat.mitre_techniques:
        return []

    stmt = select(MitreTechnique).where(MitreTechnique.id.in_(threat.mitre_techniques))
    res = await db.execute(stmt)
    return list(res.scalars().all())


@router.get("/{threat_id}/risk")
async def get_threat_risk_breakdown(threat_id: str, db: AsyncSession = Depends(get_db)):
    """Returns detailed risk scoring factors for transparency."""
    threat = await db.get(Threat, threat_id)
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "THREAT_NOT_FOUND", "message": f"Threat {threat_id} not found"}},
        )

    return {
        "threatId": threat.id,
        "confidence": threat.confidence,
        "severity": threat.severity.value,
        "priority": ThreatScoringEngine.get_priority_band(threat.confidence),
        "factors": {
            "alertCount": len(threat.alert_ids),
            "techniqueCount": len(threat.mitre_techniques),
            "status": threat.status.value,
        }
    }


@router.post(
    "/correlate",
    response_model=CorrelationResult,
    dependencies=[Depends(require_permission(Permission.CORRELATION_RUN))],
)
async def trigger_correlation(db: AsyncSession = Depends(get_db)):
    """Triggers the deterministic correlation engine over all alerts. Requires CORRELATION_RUN permission."""
    correlations_found = await CorrelationEngine.correlate_alerts(db)
    await db.commit()

    return CorrelationResult(
        correlated_incidents_created=0,
        correlations_identified=correlations_found,
        alerts_processed=100,
        details=[f"Evaluated alert relationships. {correlations_found} new correlation links established."]
    )
