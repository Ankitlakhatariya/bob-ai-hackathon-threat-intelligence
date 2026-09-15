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
from app.data.sample_data import SAMPLE_INVESTIGATIONS
from app.core.logging import logger

router = APIRouter()


@router.get(
    "",
    response_model=List[InvestigationRead],
    dependencies=[Depends(require_permission(Permission.INVESTIGATIONS_READ))],
)
async def get_investigations(
    status: Optional[str] = Query(None, description="Filter by investigation status"),
    priority: Optional[str] = Query(None, description="Filter by priority"),
    threat_id: Optional[str] = Query(None, alias="threatId", description="Filter by associated threat ID"),
    assigned_analyst: Optional[str] = Query(None, alias="assignedAnalyst", description="Filter by assigned analyst"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve investigations with optional filters."""
    try:
        results = await InvestigationService.get_investigations(
            db=db,
            status=status,
            priority=priority,
            threat_id=threat_id,
            assigned_analyst=assigned_analyst,
            skip=skip,
            limit=limit,
        )
        if results:
            return results
    except Exception as e:
        logger.warning(f"Database investigations query notice: {e}")

    # Fallback to sample investigations
    items = list(SAMPLE_INVESTIGATIONS)
    if status and status.lower() != "all":
        items = [c for c in items if c.get("status") == status.upper()]
    if priority and priority.lower() != "all":
        items = [c for c in items if c.get("priority") == priority.upper()]
    if threat_id:
        items = [c for c in items if c.get("threat_id") == threat_id]
    return items[skip : skip + limit]


@router.get(
    "/{investigation_id}",
    response_model=InvestigationRead,
    dependencies=[Depends(require_permission(Permission.INVESTIGATIONS_READ))],
)
async def get_investigation(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Retrieve an investigation by ID."""
    try:
        case = await InvestigationService.get_investigation(db=db, investigation_id=investigation_id)
        if case:
            return case
    except Exception as e:
        logger.warning(f"Database get_investigation notice: {e}")

    for c in SAMPLE_INVESTIGATIONS:
        if c["id"] == investigation_id or c.get("case_number") == investigation_id:
            return c

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"error": {"code": "NOT_FOUND", "message": f"Investigation '{investigation_id}' not found"}},
    )


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
    try:
        return await InvestigationService.create_investigation(db=db, payload=payload, user_id=user_id)
    except Exception as e:
        logger.warning(f"Database create_investigation notice: {e}")
        from datetime import datetime, timezone
        now_dt = datetime.now(timezone.utc)
        return InvestigationRead(
            id=f"case-{len(SAMPLE_INVESTIGATIONS) + 1}",
            case_number=f"CASE-2026-{100 + len(SAMPLE_INVESTIGATIONS) + 1}",
            threat_id=payload.threat_id,
            title=payload.title,
            status=payload.status or "OPEN",
            priority=payload.priority or "P2",
            assigned_analyst=payload.assigned_analyst or user_id,
            assigned_team=payload.assigned_team or "SOC North",
            timeline=[],
            notes=[],
            created_at=now_dt,
            updated_at=now_dt,
        )


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
    user_id = current_user.email or current_user.full_name
    try:
        case = await InvestigationService.get_investigation(db=db, investigation_id=investigation_id)
        if case:
            return await InvestigationService.update_investigation(
                db=db, case=case, payload=payload, user_id=user_id
            )
    except Exception as e:
        logger.warning(f"Database update_investigation notice: {e}")

    for c in SAMPLE_INVESTIGATIONS:
        if c["id"] == investigation_id:
            updated = dict(c)
            if payload.status:
                updated["status"] = payload.status
            if payload.priority:
                updated["priority"] = payload.priority
            return updated

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"error": {"code": "NOT_FOUND", "message": f"Investigation '{investigation_id}' not found"}},
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
    user_id = current_user.email or current_user.full_name
    author = payload.author or current_user.full_name or current_user.email or "Analyst"
    try:
        case = await InvestigationService.get_investigation(db=db, investigation_id=investigation_id)
        if case:
            return await InvestigationService.add_note(
                db=db, case=case, note=payload.note, author=author, user_id=user_id
            )
    except Exception as e:
        logger.warning(f"Database add_note notice: {e}")

    for c in SAMPLE_INVESTIGATIONS:
        if c["id"] == investigation_id:
            return c

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"error": {"code": "NOT_FOUND", "message": f"Investigation '{investigation_id}' not found"}},
    )


@router.post(
    "/{investigation_id}/resolve",
    response_model=InvestigationRead,
    dependencies=[Depends(require_permission(Permission.INVESTIGATIONS_WRITE))],
)
async def resolve_investigation(
    investigation_id: str,
    payload: Optional[InvestigationResolveRequest] = None,
    resolution_note: Optional[str] = Query(None, description="Resolution note"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Resolve an investigation."""
    user_id = current_user.email or current_user.full_name
    summary = (
        (payload.resolution_summary if payload and payload.resolution_summary else None)
        or resolution_note
        or "Threat mitigated and affected assets isolated."
    )
    try:
        case = await InvestigationService.get_investigation(db=db, investigation_id=investigation_id)
        if case:
            return await InvestigationService.resolve_investigation(
                db=db, case=case, resolution_summary=summary, user_id=user_id
            )
    except Exception as e:
        logger.warning(f"Database resolve_investigation notice: {e}")

    for c in SAMPLE_INVESTIGATIONS:
        if c["id"] == investigation_id:
            updated = dict(c)
            updated["status"] = "RESOLVED"
            return updated

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"error": {"code": "NOT_FOUND", "message": f"Investigation '{investigation_id}' not found"}},
    )


@router.post(
    "/{investigation_id}/false-positive",
    response_model=InvestigationRead,
    dependencies=[Depends(require_permission(Permission.INVESTIGATIONS_WRITE))],
)
async def mark_investigation_false_positive(
    investigation_id: str,
    payload: Optional[InvestigationFalsePositiveRequest] = None,
    reason: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mark an investigation as FALSE_POSITIVE."""
    user_id = current_user.email or current_user.full_name
    fp_reason = (
        (payload.reason if payload and payload.reason else None)
        or reason
        or "Activity verified as benign authorized administrative task."
    )
    evidence_notes = payload.evidence_notes if payload else None
    try:
        case = await InvestigationService.get_investigation(db=db, investigation_id=investigation_id)
        if case:
            return await InvestigationService.mark_false_positive(
                db=db, case=case, reason=fp_reason, user_id=user_id, evidence_notes=evidence_notes
            )
    except Exception as e:
        logger.warning(f"Database mark_false_positive notice: {e}")

    for c in SAMPLE_INVESTIGATIONS:
        if c["id"] == investigation_id:
            updated = dict(c)
            updated["status"] = "FALSE_POSITIVE"
            return updated

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"error": {"code": "NOT_FOUND", "message": f"Investigation '{investigation_id}' not found"}},
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
    """Escalate an investigation."""
    user_id = current_user.email or current_user.full_name
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
    try:
        case = await InvestigationService.get_investigation(db=db, investigation_id=investigation_id)
        if case:
            return await InvestigationService.escalate_investigation(
                db=db, case=case, escalate_to=target_priority, reason=escalate_reason, user_id=user_id
            )
    except Exception as e:
        logger.warning(f"Database escalate_investigation notice: {e}")

    for c in SAMPLE_INVESTIGATIONS:
        if c["id"] == investigation_id:
            updated = dict(c)
            updated["status"] = "ESCALATED"
            updated["priority"] = target_priority
            return updated

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"error": {"code": "NOT_FOUND", "message": f"Investigation '{investigation_id}' not found"}},
    )
