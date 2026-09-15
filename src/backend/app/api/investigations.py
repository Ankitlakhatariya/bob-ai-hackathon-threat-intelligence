from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, Body, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db, require_permission, get_current_user
from app.core.permissions import Permission
from app.models.user import User
from app.models.investigation import Investigation
from app.schemas.investigation import (
    InvestigationRead,
    InvestigationCreate,
    InvestigationUpdate,
    InvestigationNoteCreate,
    InvestigationResolveRequest,
    InvestigationFalsePositiveRequest,
    InvestigationEscalateRequest,
)
from app.services.investigation_service import InvestigationService

router = APIRouter()


@router.get(
    "",
    response_model=List[InvestigationRead],
    dependencies=[Depends(require_permission(Permission.INVESTIGATIONS_READ))],
)
async def get_investigations(
    status: Optional[str] = Query(None, description="Filter by investigation status (OPEN, IN_PROGRESS, ESCALATED, RESOLVED, FALSE_POSITIVE, CLOSED)"),
    priority: Optional[str] = Query(None, description="Filter by priority (P1, P2, P3, P4, CRITICAL, HIGH, MEDIUM, LOW)"),
    threat_id: Optional[str] = Query(None, alias="threatId", description="Filter by associated threat ID"),
    assigned_analyst: Optional[str] = Query(None, alias="assignedAnalyst", description="Filter by assigned analyst name or email"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve investigations with optional status, priority, threat, and analyst filters."""
    return await InvestigationService.get_investigations(
        db=db,
        status=status,
        priority=priority,
        threat_id=threat_id,
        assigned_analyst=assigned_analyst,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/{investigation_id}",
    response_model=InvestigationRead,
    dependencies=[Depends(require_permission(Permission.INVESTIGATIONS_READ))],
)
async def get_investigation(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Retrieve an investigation by ID (UUID or string identifier)."""
    case = await InvestigationService.get_investigation(db=db, investigation_id=investigation_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": f"Investigation '{investigation_id}' not found"}},
        )
    return case


@router.post(
    "",
    response_model=InvestigationRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.INVESTIGATIONS_WRITE))],
)
async def create_investigation(
    payload: InvestigationCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new threat investigation case."""
    user_id = current_user.email or current_user.full_name
    return await InvestigationService.create_investigation(db=db, payload=payload, user_id=user_id)


@router.patch(
    "/{investigation_id}",
    response_model=InvestigationRead,
    dependencies=[Depends(require_permission(Permission.INVESTIGATIONS_WRITE))],
)
async def update_investigation(
    investigation_id: str,
    payload: InvestigationUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update investigation details, status, priority, or assigned analyst."""
    case = await InvestigationService.get_investigation(db=db, investigation_id=investigation_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": f"Investigation '{investigation_id}' not found"}},
        )

    user_id = current_user.email or current_user.full_name
    return await InvestigationService.update_investigation(
        db=db, case=case, payload=payload, user_id=user_id
    )


@router.post(
    "/{investigation_id}/notes",
    response_model=InvestigationRead,
    dependencies=[Depends(require_permission(Permission.INVESTIGATIONS_WRITE))],
)
async def add_investigation_note(
    investigation_id: str,
    payload: InvestigationNoteCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add an analyst note to the investigation timeline and audit log."""
    case = await InvestigationService.get_investigation(db=db, investigation_id=investigation_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": f"Investigation '{investigation_id}' not found"}},
        )

    author = payload.author or current_user.full_name or current_user.email or "Analyst"
    user_id = current_user.email or current_user.full_name
    return await InvestigationService.add_note(
        db=db, case=case, note=payload.note, author=author, user_id=user_id
    )


@router.post(
    "/{investigation_id}/resolve",
    response_model=InvestigationRead,
    dependencies=[Depends(require_permission(Permission.INVESTIGATIONS_WRITE))],
)
async def resolve_investigation(
    investigation_id: str,
    payload: Optional[InvestigationResolveRequest] = None,
    resolution_note: Optional[str] = Query(None, description="Resolution note if not provided in JSON body"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Resolve an investigation and transition associated threat/alert statuses."""
    case = await InvestigationService.get_investigation(db=db, investigation_id=investigation_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": f"Investigation '{investigation_id}' not found"}},
        )

    summary = (
        (payload.resolution_summary if payload and payload.resolution_summary else None)
        or resolution_note
        or "Threat mitigated and affected assets isolated."
    )
    user_id = current_user.email or current_user.full_name
    return await InvestigationService.resolve_investigation(
        db=db, case=case, resolution_summary=summary, user_id=user_id
    )


@router.post(
    "/{investigation_id}/false-positive",
    response_model=InvestigationRead,
    dependencies=[Depends(require_permission(Permission.INVESTIGATIONS_WRITE))],
)
async def mark_investigation_false_positive(
    investigation_id: str,
    payload: Optional[InvestigationFalsePositiveRequest] = None,
    reason: Optional[str] = Query(None, description="False positive justification if not provided in body"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Mark an investigation as FALSE_POSITIVE.
    CRITICAL RULE: Telemetry evidence and raw alerts are NEVER deleted.
    """
    case = await InvestigationService.get_investigation(db=db, investigation_id=investigation_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": f"Investigation '{investigation_id}' not found"}},
        )

    fp_reason = (
        (payload.reason if payload and payload.reason else None)
        or reason
        or "Activity verified as benign authorized administrative task."
    )
    evidence_notes = payload.evidence_notes if payload else None
    user_id = current_user.email or current_user.full_name

    return await InvestigationService.mark_false_positive(
        db=db,
        case=case,
        reason=fp_reason,
        user_id=user_id,
        evidence_notes=evidence_notes,
    )


@router.post(
    "/{investigation_id}/escalate",
    response_model=InvestigationRead,
    dependencies=[Depends(require_permission(Permission.INVESTIGATIONS_WRITE))],
)
async def escalate_investigation(
    investigation_id: str,
    payload: Optional[InvestigationEscalateRequest] = None,
    escalate_to: Optional[str] = Query(None, pattern="^(P1|P2|P3|P4|CRITICAL|HIGH|MEDIUM|LOW)$"),
    reason: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Escalate an investigation to ESCALATED status with elevated priority."""
    case = await InvestigationService.get_investigation(db=db, investigation_id=investigation_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": f"Investigation '{investigation_id}' not found"}},
        )

    target_priority = (
        (payload.escalate_to if payload and payload.escalate_to else None)
        or escalate_to
        or "P1"
    )
    escalate_reason = (
        (payload.reason if payload and payload.reason else None)
        or reason
        or "Escalated for immediate containment and response."
    )
    user_id = current_user.email or current_user.full_name

    return await InvestigationService.escalate_investigation(
        db=db,
        case=case,
        escalate_to=target_priority,
        reason=escalate_reason,
        user_id=user_id,
    )

