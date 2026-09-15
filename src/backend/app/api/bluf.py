from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.dependencies import get_db
from app.schemas.bluf import BlufReportRead, BlufGenerateRequest
from app.services.bluf_service import BlufService
from app.data.sample_data import SAMPLE_BRIEFS
from app.core.logging import logger

router = APIRouter()


@router.get("", response_model=Dict[str, BlufReportRead])
async def get_all_bluf_briefs(db: AsyncSession = Depends(get_db)):
    """Returns map of incident ID to BLUF brief matching frontend mockBriefs."""
    try:
        briefs = await BlufService.get_all_briefs_dict(db)
        if briefs:
            return briefs
    except Exception as e:
        logger.warning(f"Database bluf briefs query notice: {e}")

    return SAMPLE_BRIEFS


@router.get("/{threat_id}", response_model=BlufReportRead)
async def get_bluf_report(threat_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieves single BLUF report for an incident."""
    try:
        report = await BlufService.get_or_generate_bluf(db, threat_id)
        if report:
            return report
    except Exception as e:
        logger.warning(f"Database bluf report query notice: {e}")

    if threat_id in SAMPLE_BRIEFS:
        return SAMPLE_BRIEFS[threat_id]

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"error": {"code": "NOT_FOUND", "message": f"No brief found for incident {threat_id}"}},
    )


@router.post("/{threat_id}/generate", response_model=BlufReportRead)
async def generate_bluf_report(threat_id: str, db: AsyncSession = Depends(get_db)):
    """Generates / refreshes an executive BLUF brief for an incident."""
    try:
        report = await BlufService.get_or_generate_bluf(db, threat_id, force_regenerate=True)
        if report:
            return report
    except Exception as e:
        logger.warning(f"Database generate bluf notice: {e}")

    if threat_id in SAMPLE_BRIEFS:
        return SAMPLE_BRIEFS[threat_id]

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"error": {"code": "NOT_FOUND", "message": f"Threat {threat_id} not found"}},
    )
