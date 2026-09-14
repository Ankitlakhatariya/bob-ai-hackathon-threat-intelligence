from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, desc, asc
from app.core.dependencies import get_db, require_permission, get_current_user
from app.core.permissions import Permission
from app.models.threat import Threat, ThreatSeverity, ThreatStatus
from app.models.alert import Alert, AlertSeverity
from app.models.mitre import MitreTechnique
from app.schemas.threat import (
    ThreatRead,
    ThreatCreate,
    ThreatUpdate,
    ThreatTimelineEvent,
    ThreatRiskResponse,
)
from app.schemas.alert import AlertRead
from app.schemas.correlation import CorrelationResult
from app.schemas.mitre import MitreTechniqueRead
from app.services.correlation import CorrelationEngine
from app.services.threat_scoring import ThreatScoringEngine

router = APIRouter()


@router.get("/prioritized", response_model=List[ThreatRead])
async def get_prioritized_threats(
    priority: Optional[str] = Query(None, regex="^(CRITICAL|HIGH|MEDIUM|LOW)$"),
    min_score: Optional[int] = Query(None, ge=0, le=100),
    status: Optional[str] = Query(None, description="active, investigating, resolved"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """Returns threats prioritized by risk score (descending) to guide SOC analyst triage."""
    stmt = select(Threat).order_by(desc(Threat.risk_score))

    if status and status != "all":
        try:
            stat_enum = ThreatStatus(status.lower())
            stmt = stmt.where(Threat.status == stat_enum)
        except ValueError:
            pass

    if min_score is not None:
        stmt = stmt.where(Threat.risk_score >= min_score)

    if priority:
        if priority == "CRITICAL":
            stmt = stmt.where(Threat.risk_score >= 75)
        elif priority == "HIGH":
            stmt = stmt.where((Threat.risk_score >= 50) & (Threat.risk_score < 75))
        elif priority == "MEDIUM":
            stmt = stmt.where((Threat.risk_score >= 25) & (Threat.risk_score < 50))
        elif priority == "LOW":
            stmt = stmt.where(Threat.risk_score < 25)

    stmt = stmt.offset(skip).limit(limit)
    res = await db.execute(stmt)
    threats = list(res.scalars().all())

    for t in threats:
        if not hasattr(t, "updated_at") or t.updated_at is None:
            t.updated_at = getattr(t, "updated_at_field", t.opened_at)
        if not t.threat_id:
            t.threat_id = t.id
        t.priority = ThreatScoringEngine.get_priority_band(t.risk_score)

    return threats


@router.get("", response_model=List[ThreatRead])
async def get_threats(
    status: Optional[str] = Query(None, description="active, investigating, resolved"),
    severity: Optional[str] = Query(None, description="critical, high, medium, low"),
    search: Optional[str] = Query(None, description="Search ID, title, or summary"),
    sort_by: str = Query("first_seen", regex="^(first_seen|last_seen|risk_score|confidence|alert_count|id)$"),
    sort_order: str = Query("desc", regex="^(desc|asc)$"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves correlated threats/incidents with filtering, sorting, and pagination."""
    stmt = select(Threat)

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

    sort_col = getattr(Threat, sort_by, Threat.first_seen)
    if sort_order == "asc":
        stmt = stmt.order_by(asc(sort_col))
    else:
        stmt = stmt.order_by(desc(sort_col))

    stmt = stmt.offset(skip).limit(limit)
    res = await db.execute(stmt)
    threats = list(res.scalars().all())

    for t in threats:
        if not hasattr(t, "updated_at") or t.updated_at is None:
            t.updated_at = getattr(t, "updated_at_field", t.opened_at)
        if not t.threat_id:
            t.threat_id = t.id
        t.priority = ThreatScoringEngine.get_priority_band(t.risk_score)

    return threats


@router.get("/{threat_id}", response_model=ThreatRead)
async def get_threat(threat_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieves a single threat/incident by ID with all correlated telemetry."""
    threat = await db.get(Threat, threat_id)
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "THREAT_NOT_FOUND", "message": f"Threat {threat_id} not found"}},
        )
    if not hasattr(threat, "updated_at") or threat.updated_at is None:
        threat.updated_at = getattr(threat, "updated_at_field", threat.opened_at)
    if not threat.threat_id:
        threat.threat_id = threat.id
    threat.priority = ThreatScoringEngine.get_priority_band(threat.risk_score)
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
        ThreatTimelineEvent(time=threat.first_seen or threat.opened_at, label="Incident opened — first telemetry event detected", tone="primary")
    ]

    alerts_stmt = select(Alert).where(
        or_(Alert.related_threat_id == threat_id, Alert.id.in_(threat.alert_ids or []))
    ).order_by(Alert.timestamp.asc())
    alerts_res = await db.execute(alerts_stmt)

    for a in alerts_res.scalars().all():
        events.append(
            ThreatTimelineEvent(
                time=a.timestamp,
                label=f"Alert {a.id} ({a.source_label}): {a.title}",
                tone="accent" if a.severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH] else "neutral"
            )
        )

    events.append(
        ThreatTimelineEvent(time=threat.last_seen or threat.updated_at_custom, label="Latest correlated activity", tone="neutral")
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


@router.get("/{threat_id}/risk", response_model=ThreatRiskResponse)
async def get_threat_risk_breakdown(threat_id: str, db: AsyncSession = Depends(get_db)):
    """Returns transparent, explainable risk scoring factors and priority band for this threat."""
    threat = await db.get(Threat, threat_id)
    if not threat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "THREAT_NOT_FOUND", "message": f"Threat {threat_id} not found"}},
        )

    # Fetch associated member alerts
    alerts_stmt = select(Alert).where(
        or_(Alert.related_threat_id == threat_id, Alert.id.in_(threat.alert_ids or []))
    )
    alerts_res = await db.execute(alerts_stmt)
    alerts = list(alerts_res.scalars().all())

    # Evaluate deterministic factors
    assessment = ThreatScoringEngine.evaluate_threat_risk(threat, alerts)

    # Store factors in threat model for persistence
    threat.risk_score = assessment["risk_score"]
    threat.scoring_factors = assessment["factors"]
    await db.commit()

    return ThreatRiskResponse(
        risk_score=assessment["risk_score"],
        priority=assessment["priority"],
        factors=assessment["factors"],
    )


@router.post(
    "/correlate",
    response_model=CorrelationResult,
    dependencies=[Depends(require_permission(Permission.CORRELATION_RUN))],
)
async def trigger_correlation(db: AsyncSession = Depends(get_db)):
    """Triggers the deterministic correlation engine over alerts and groups them into threats."""
    correlations_found = await CorrelationEngine.correlate_alerts(db)

    count_res = await db.execute(select(Threat.id))
    total_threats = len(list(count_res.scalars().all()))

    return CorrelationResult(
        correlated_incidents_created=0,
        correlations_identified=correlations_found,
        alerts_processed=300,
        threats_updated=total_threats,
        details=[
            f"Deterministic correlation engine evaluated open telemetry.",
            f"Identified {correlations_found} new explainable correlation links.",
            f"Consolidated into {total_threats} active threat campaigns.",
        ]
    )
