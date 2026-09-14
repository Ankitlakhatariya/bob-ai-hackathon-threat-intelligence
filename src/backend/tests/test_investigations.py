import pytest
import uuid
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import select

from app.database.database import Base
from app.models.investigation import Investigation, InvestigationStatus, InvestigationPriority
from app.models.threat import Threat, ThreatStatus, ThreatSeverity
from app.models.alert import Alert, AlertStatus, AlertSeverity, AlertSource
from app.models.audit_log import AuditLog
from app.schemas.investigation import (
    InvestigationCreate,
    InvestigationUpdate,
    InvestigationNoteCreate,
    InvestigationResolveRequest,
    InvestigationFalsePositiveRequest,
    InvestigationEscalateRequest,
)
from app.services.investigation_service import InvestigationService


@pytest.fixture
async def db_session():
    """In-memory SQLite database session for unit testing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with async_session() as session:
        yield session

    await engine.dispose()


@pytest.mark.asyncio
async def test_create_investigation(db_session: AsyncSession):
    """Test investigation creation and audit log generation."""
    payload = InvestigationCreate(
        title="Suspicious C2 Beaconing Investigation",
        threat_id="THREAT-5001",
        assigned_analyst="analyst.alice@threatlens.soc",
        priority=InvestigationPriority.P1,
        notes="Detected multiple outbound beacons to suspect dynamic DNS domain.",
        findings="Initial staging in %TEMP% observed.",
    )

    case = await InvestigationService.create_investigation(
        db=db_session, payload=payload, user_id="analyst.alice@threatlens.soc"
    )

    assert case.id is not None
    assert case.title == "Suspicious C2 Beaconing Investigation"
    assert case.status == InvestigationStatus.OPEN
    assert case.priority == InvestigationPriority.P1
    assert case.assigned_to == "analyst.alice@threatlens.soc"
    assert case.assigned_analyst == "analyst.alice@threatlens.soc"
    assert case.closed_at is None

    # Verify audit log was recorded
    stmt = select(AuditLog).where(AuditLog.entity_id == str(case.id))
    res = await db_session.execute(stmt)
    audit = res.scalars().first()
    assert audit is not None
    assert audit.action == "INVESTIGATION_CREATED"
    assert audit.user_id == "analyst.alice@threatlens.soc"


@pytest.mark.asyncio
async def test_add_investigation_note(db_session: AsyncSession):
    """Test adding sequential analyst notes to the case history."""
    payload = InvestigationCreate(
        threat_id="THREAT-5002",
        assigned_analyst="analyst.bob@threatlens.soc",
        priority=InvestigationPriority.P2,
    )
    case = await InvestigationService.create_investigation(db=db_session, payload=payload)

    updated_case = await InvestigationService.add_note(
        db=db_session,
        case=case,
        note="Host endpoint isolated from subnet at 22:45 UTC.",
        author="Analyst Bob",
        user_id="analyst.bob@threatlens.soc",
    )

    assert "Host endpoint isolated" in updated_case.notes
    assert "Analyst Bob" in updated_case.notes

    # Check note audit log
    stmt = select(AuditLog).where(
        AuditLog.entity_id == str(case.id),
        AuditLog.action == "INVESTIGATION_NOTE_ADDED",
    )
    res = await db_session.execute(stmt)
    audit = res.scalars().first()
    assert audit is not None
    assert audit.details["author"] == "Analyst Bob"


@pytest.mark.asyncio
async def test_resolve_investigation(db_session: AsyncSession):
    """Test resolving an investigation, verifying threat state transition and timestamp."""
    # Seed threat
    threat = Threat(
        id="THREAT-6001",
        title="Kerberoasting Activity",
        summary="Service ticket requests detected",
        severity=ThreatSeverity.HIGH,
        status=ThreatStatus.ACTIVE,
    )
    db_session.add(threat)
    await db_session.commit()

    # Create investigation
    payload = InvestigationCreate(
        threat_id="THREAT-6001",
        assigned_analyst="analyst.charlie@threatlens.soc",
    )
    case = await InvestigationService.create_investigation(db=db_session, payload=payload)

    # Resolve investigation
    resolved_case = await InvestigationService.resolve_investigation(
        db=db_session,
        case=case,
        resolution_summary="Compromised service account reset and Kerberos ticket lifetime restricted.",
        user_id="analyst.charlie@threatlens.soc",
    )

    assert resolved_case.status == InvestigationStatus.RESOLVED
    assert resolved_case.closed_at is not None
    assert "Compromised service account reset" in resolved_case.resolution_summary

    # Verify linked threat status updated to RESOLVED
    await db_session.refresh(threat)
    assert threat.status == ThreatStatus.RESOLVED


@pytest.mark.asyncio
async def test_mark_false_positive_preserves_evidence(db_session: AsyncSession):
    """
    CRITICAL TEST: Ensure marking an investigation as false positive:
    1. Sets status to FALSE_POSITIVE
    2. NEVER deletes raw alert telemetry, event logs, or correlation linkages
    3. Explicitly records evidence preservation in audit trail
    """
    # Seed alert with rich raw data and telemetry
    alert = Alert(
        id="ALERT-9001",
        title="PowerShell Encoded Command",
        description="powershell.exe -EncodedCommand ...",
        source=AlertSource.EDR,
        source_label="CrowdStrike Falcon",
        severity=AlertSeverity.HIGH,
        status=AlertStatus.OPEN,
        raw_data={"cmdline": "powershell.exe -EncodedCommand dGVzdA==", "user": "SYSTEM"},
        indicators=["192.168.1.100"],
    )
    db_session.add(alert)
    await db_session.commit()

    # Create investigation for this alert
    payload = InvestigationCreate(
        alert_id="ALERT-9001",
        title="Investigation on Alert-9001",
        assigned_analyst="analyst.david@threatlens.soc",
    )
    case = await InvestigationService.create_investigation(db=db_session, payload=payload)

    # Mark as false positive
    fp_reason = "Verified scheduled backup maintenance script executed by authorized SCCM policy."
    fp_case = await InvestigationService.mark_false_positive(
        db=db_session,
        case=case,
        reason=fp_reason,
        user_id="analyst.david@threatlens.soc",
        evidence_notes="Verified against IT Ticket #CHG-4921.",
    )

    assert fp_case.status == InvestigationStatus.FALSE_POSITIVE
    assert fp_case.closed_at is not None
    assert "FALSE POSITIVE" in fp_case.resolution_summary

    # EVIDENCE PRESERVATION ASSERTIONS:
    # 1. Alert must still exist in DB (NOT deleted)
    retrieved_alert = await db_session.get(Alert, "ALERT-9001")
    assert retrieved_alert is not None
    assert retrieved_alert.status == AlertStatus.FALSE_POSITIVE
    # 2. Raw data and indicators must remain intact
    assert retrieved_alert.raw_data == {"cmdline": "powershell.exe -EncodedCommand dGVzdA==", "user": "SYSTEM"}
    assert retrieved_alert.indicators == ["192.168.1.100"]

    # 3. Audit trail confirms non-deletion
    stmt = select(AuditLog).where(
        AuditLog.entity_id == str(case.id),
        AuditLog.action == "INVESTIGATION_FALSE_POSITIVE",
    )
    res = await db_session.execute(stmt)
    audit = res.scalars().first()
    assert audit is not None
    assert audit.details["evidence_preserved"] is True
    assert audit.details["reason"] == fp_reason


@pytest.mark.asyncio
async def test_escalate_investigation(db_session: AsyncSession):
    """Test escalating investigation priority and setting ESCALATED status."""
    payload = InvestigationCreate(
        threat_id="THREAT-7001",
        priority=InvestigationPriority.P3,
        assigned_analyst="analyst.eve@threatlens.soc",
    )
    case = await InvestigationService.create_investigation(db=db_session, payload=payload)
    assert case.priority == InvestigationPriority.P3
    assert case.status == InvestigationStatus.OPEN

    escalated_case = await InvestigationService.escalate_investigation(
        db=db_session,
        case=case,
        escalate_to="P1",
        reason="Detected lateral movement to domain controller.",
        user_id="analyst.eve@threatlens.soc",
    )

    assert escalated_case.status == InvestigationStatus.ESCALATED
    assert escalated_case.priority == InvestigationPriority.P1
    assert "ESCALATED to P1" in escalated_case.notes

    # Verify audit trail
    stmt = select(AuditLog).where(
        AuditLog.entity_id == str(case.id),
        AuditLog.action == "INVESTIGATION_ESCALATED",
    )
    res = await db_session.execute(stmt)
    audit = res.scalars().first()
    assert audit is not None
    assert audit.details["priority"] == "P1"
