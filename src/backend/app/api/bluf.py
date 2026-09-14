from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.dependencies import get_db
from app.schemas.bluf import BlufReportRead, BlufGenerateRequest
from app.services.bluf_service import BlufService

router = APIRouter()


@router.get("", response_model=Dict[str, BlufReportRead])
async def get_all_bluf_briefs(db: AsyncSession = Depends(get_db)):
    """Returns map of incident ID to BLUF brief matching frontend mockBriefs."""
    return await BlufService.get_all_briefs_dict(db)


@router.get("/{threat_id}", response_model=BlufReportRead)
async def get_bluf_report(threat_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieves single BLUF report for an incident."""
    report = await BlufService.get_or_generate_bluf(db, threat_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": f"No brief found for incident {threat_id}"}},
        )
    return report


@router.post("/{threat_id}/generate", response_model=BlufReportRead)
async def generate_bluf_report(threat_id: str, db: AsyncSession = Depends(get_db)):
    """Generates / refreshes an executive BLUF brief for an incident."""
    report = await BlufService.get_or_generate_bluf(db, threat_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": f"Threat {threat_id} not found"}},
        )
    return report
