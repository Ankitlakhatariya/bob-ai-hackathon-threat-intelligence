from typing import List, Optional
from uuid import UUID
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.dependencies import get_db
from app.models.investigation import Investigation, InvestigationStatus, InvestigationPriority
from app.models.audit_log import AuditLog
from app.schemas.investigation import (
    InvestigationRead,
    InvestigationCreate,
    InvestigationUpdate,
    InvestigationNoteCreate,
)

router = APIRouter()


@router.get("", response_model=List[InvestigationRead])
async def get_investigations(
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Investigation).order_by(Investigation.created_at.desc())
    if status:
        try:
            stat_enum = InvestigationStatus(status.lower())
            stmt = stmt.where(Investigation.status == stat_enum)
        except ValueError:
            pass
    if priority:
        try:
            prio_enum = InvestigationPriority(priority.upper())
            stmt = stmt.where(Investigation.priority == prio_enum)
        except ValueError:
            pass

    stmt = stmt.offset(skip).limit(limit)
    res = await db.execute(stmt)
    return list(res.scalars().all())


@router.get("/{investigation_id}", response_model=InvestigationRead)
async def get_investigation(investigation_id: UUID, db: AsyncSession = Depends(get_db)):
    case = await db.get(Investigation, investigation_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": f"Investigation {investigation_id} not found"}},
        )
    return case


@router.post("", response_model=InvestigationRead, status_code=status.HTTP_201_CREATED)
async def create_investigation(payload: InvestigationCreate, db: AsyncSession = Depends(get_db)):
    case = Investigation(
        title=payload.title,
        threat_id=payload.threat_id,
        alert_id=payload.alert_id,
        priority=payload.priority,
        assigned_to=payload.assigned_to,
        notes=payload.notes,
        findings=payload.findings,
        status=InvestigationStatus.OPEN,
    )
    db.add(case)
    await db.commit()
    await db.refresh(case)

    # Log audit trail
    log = AuditLog(
        action="INVESTIGATION_CREATED",
        entity_type="investigation",
        entity_id=str(case.id),
        details={"title": case.title, "priority": case.priority.value},
    )
    db.add(log)
    await db.commit()

    return case


@router.patch("/{investigation_id}", response_model=InvestigationRead)
async def update_investigation(
    investigation_id: UUID,
    payload: InvestigationUpdate,
    db: AsyncSession = Depends(get_db),
):
    case = await db.get(Investigation, investigation_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": f"Investigation {investigation_id} not found"}},
        )

    if payload.title is not None:
        case.title = payload.title
    if payload.status is not None:
        case.status = payload.status
    if payload.priority is not None:
        case.priority = payload.priority
    if payload.assigned_to is not None:
        case.assigned_to = payload.assigned_to
    if payload.notes is not None:
        case.notes = payload.notes
    if payload.findings is not None:
        case.findings = payload.findings
    if payload.resolution_summary is not None:
        case.resolution_summary = payload.resolution_summary

    await db.commit()
    await db.refresh(case)
    return case


@router.post("/{investigation_id}/notes", response_model=InvestigationRead)
async def add_investigation_note(
    investigation_id: UUID,
    payload: InvestigationNoteCreate,
    db: AsyncSession = Depends(get_db),
):
    case = await db.get(Investigation, investigation_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": f"Investigation {investigation_id} not found"}},
        )

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    new_entry = f"\n[{timestamp}] ({payload.author}): {payload.note}"
    case.notes = (case.notes or "") + new_entry

    await db.commit()
    await db.refresh(case)
    return case


@router.post("/{investigation_id}/resolve", response_model=InvestigationRead)
async def resolve_investigation(
    investigation_id: UUID,
    resolution_note: Optional[str] = Query("Threat mitigated and affected assets isolated."),
    db: AsyncSession = Depends(get_db),
):
    case = await db.get(Investigation, investigation_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": f"Investigation {investigation_id} not found"}},
        )

    case.status = InvestigationStatus.RESOLVED
    case.resolution_summary = resolution_note

    log = AuditLog(
        action="INVESTIGATION_RESOLVED",
        entity_type="investigation",
        entity_id=str(case.id),
        details={"resolution": resolution_note},
    )
    db.add(log)
    await db.commit()
    await db.refresh(case)
    return case


@router.post("/{investigation_id}/false-positive", response_model=InvestigationRead)
async def mark_investigation_false_positive(
    investigation_id: UUID,
    reason: Optional[str] = Query("Activity verified as benign authorized administrative task."),
    db: AsyncSession = Depends(get_db),
):
    case = await db.get(Investigation, investigation_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": f"Investigation {investigation_id} not found"}},
        )

    case.status = InvestigationStatus.FALSE_POSITIVE
    case.resolution_summary = f"FALSE POSITIVE: {reason}"

    log = AuditLog(
        action="INVESTIGATION_FALSE_POSITIVE",
        entity_type="investigation",
        entity_id=str(case.id),
        details={"reason": reason},
    )
    db.add(log)
    await db.commit()
    await db.refresh(case)
    return case


@router.post("/{investigation_id}/escalate", response_model=InvestigationRead)
async def escalate_investigation(
    investigation_id: UUID,
    escalate_to: str = Query("P1", regex="^(P1|P2|P3|P4)$"),
    db: AsyncSession = Depends(get_db),
):
    case = await db.get(Investigation, investigation_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": f"Investigation {investigation_id} not found"}},
        )

    case.priority = InvestigationPriority(escalate_to)

    log = AuditLog(
        action="INVESTIGATION_ESCALATED",
        entity_type="investigation",
        entity_id=str(case.id),
        details={"priority": escalate_to},
    )
    db.add(log)
    await db.commit()
    await db.refresh(case)
    return case
