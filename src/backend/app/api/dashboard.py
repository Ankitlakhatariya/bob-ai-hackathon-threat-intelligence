from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.core.dependencies import get_db
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.threat import Threat, ThreatStatus
from app.models.data_source import DataSource, DataSourceStatus
from app.schemas.dashboard import DashboardOverview, SeverityDistributionItem, SystemStatusItem
from app.schemas.alert import TrendPointResponse
from app.schemas.threat import ThreatRead
from app.services.threat_scoring import ThreatScoringEngine

router = APIRouter()


@router.get("/overview", response_model=DashboardOverview)
@router.get("/summary", response_model=DashboardOverview)
async def get_dashboard_overview(db: AsyncSession = Depends(get_db)):
    """Provides key operational stats for the top cards on the dashboard."""
    # Open / investigating alerts
    open_alerts_res = await db.execute(
        select(func.count(Alert.id)).where(Alert.status.in_([AlertStatus.OPEN, AlertStatus.INVESTIGATING]))
    )
    total_open = open_alerts_res.scalar() or 0

    # Critical open alerts
    crit_res = await db.execute(
        select(func.count(Alert.id)).where(
            (Alert.severity == AlertSeverity.CRITICAL) &
            (Alert.status.in_([AlertStatus.OPEN, AlertStatus.INVESTIGATING]))
        )
    )
    critical = crit_res.scalar() or 0

    # Incidents / threats count
    threats_res = await db.execute(select(func.count(Threat.id)))
    incident_count = threats_res.scalar() or 0

    # False positive review queue (low severity open alerts)
    fp_res = await db.execute(
        select(func.count(Alert.id)).where(
            (Alert.severity == AlertSeverity.LOW) & (Alert.status == AlertStatus.OPEN)
        )
    )
    false_pos_review = fp_res.scalar() or 0

    return DashboardOverview(
        total_open=total_open,
        critical=critical,
        incident_count=incident_count,
        false_positive_review=false_pos_review,
    )


@router.get("/severity-distribution", response_model=List[SeverityDistributionItem])
async def get_severity_distribution(db: AsyncSession = Depends(get_db)):
    """Returns alert counts grouped by severity."""
    order = [AlertSeverity.CRITICAL, AlertSeverity.HIGH, AlertSeverity.MEDIUM, AlertSeverity.LOW]
    result = []
    for sev in order:
        count_res = await db.execute(select(func.count(Alert.id)).where(Alert.severity == sev))
        count = count_res.scalar() or 0
        result.append(SeverityDistributionItem(severity=sev, count=count))
    return result


@router.get("/alert-trends", response_model=List[TrendPointResponse])
async def get_dashboard_alert_trends():
    """Returns sample trend timeline for alerts."""
    return [
        TrendPointResponse(label="00:00", alerts=42, incidents=3),
        TrendPointResponse(label="04:00", alerts=28, incidents=2),
        TrendPointResponse(label="08:00", alerts=65, incidents=5),
        TrendPointResponse(label="12:00", alerts=94, incidents=8),
        TrendPointResponse(label="16:00", alerts=81, incidents=6),
        TrendPointResponse(label="20:00", alerts=53, incidents=4),
    ]


@router.get("/threat-trends", response_model=List[TrendPointResponse])
async def get_dashboard_threat_trends():
    return [
        TrendPointResponse(label="Mon", alerts=312, incidents=18),
        TrendPointResponse(label="Tue", alerts=285, incidents=14),
        TrendPointResponse(label="Wed", alerts=420, incidents=24),
        TrendPointResponse(label="Thu", alerts=390, incidents=21),
        TrendPointResponse(label="Fri", alerts=465, incidents=28),
        TrendPointResponse(label="Sat", alerts=180, incidents=9),
        TrendPointResponse(label="Sun", alerts=145, incidents=7),
    ]


@router.get("/top-techniques")
async def get_top_techniques(db: AsyncSession = Depends(get_db)):
    """Returns most prevalent MITRE ATT&CK techniques seen across alerts."""
    stmt = select(Alert.mitre_techniques)
    res = await db.execute(stmt)
    technique_counts = {}
    for row in res.scalars():
        for tech in row or []:
            technique_counts[tech] = technique_counts.get(tech, 0) + 1

    sorted_techniques = sorted(
        [{"techniqueId": k, "count": v} for k, v in technique_counts.items()],
        key=lambda x: x["count"],
        reverse=True,
    )
    return sorted_techniques[:5]


@router.get("/recent-threats", response_model=List[ThreatRead])
async def get_recent_threats(db: AsyncSession = Depends(get_db)):
    """Returns most recent threat campaigns."""
    stmt = select(Threat).order_by(Threat.opened_at.desc()).limit(5)
    res = await db.execute(stmt)
    threats = list(res.scalars().all())
    for t in threats:
        if not hasattr(t, "updated_at") or t.updated_at is None:
            t.updated_at = getattr(t, "updated_at_field", t.opened_at)
    return threats


@router.get("/system-status", response_model=List[SystemStatusItem])
async def get_system_status(db: AsyncSession = Depends(get_db)):
    """Returns telemetry feeds health status matching frontend cards."""
    stmt = select(DataSource)
    res = await db.execute(stmt)
    sources = list(res.scalars().all())

    if not sources:
        # Pre-seed standard sources from frontend
        default_sources = [
            DataSource(id="siem", name="SIEM ingestion", detail="QRadar · healthy · 12s lag", health=DataSourceStatus.HEALTHY),
            DataSource(id="edr", name="Endpoint detection", detail="All agents reporting", health=DataSourceStatus.HEALTHY),
            DataSource(id="network", name="Network sensors", detail="Segment 4 degraded · 1 sensor offline", health=DataSourceStatus.DEGRADED),
            DataSource(id="threatintel", name="Threat intel feed", detail="Last update 3 min ago", health=DataSourceStatus.HEALTHY),
            DataSource(id="correlation", name="Correlation engine", detail="Jobs running normally", health=DataSourceStatus.OPERATIONAL),
        ]
        for s in default_sources:
            db.add(s)
        await db.commit()
        stmt = select(DataSource)
        res = await db.execute(stmt)
        sources = list(res.scalars().all())

    return sources
