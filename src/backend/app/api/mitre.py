from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.dependencies import get_db
from app.models.mitre import MitreTactic, MitreTechnique
from app.schemas.mitre import MitreTacticRead, MitreTechniqueRead
from app.services.mitre_service import MitreService
from app.data.sample_data import SAMPLE_TECHNIQUES, SAMPLE_TACTICS
from app.core.logging import logger

router = APIRouter()


@router.get("", response_model=List[MitreTechniqueRead])
@router.get("/techniques", response_model=List[MitreTechniqueRead])
async def get_mitre_techniques(
    tactic: Optional[str] = Query(None, description="Initial Access, Execution, etc."),
    subtechniques: Optional[bool] = Query(None, description="Filter by sub-technique status"),
    db: AsyncSession = Depends(get_db),
):
    """Returns verified MITRE ATT&CK techniques and sub-techniques catalogue."""
    try:
        techniques = await MitreService.get_all_techniques(db, tactic=tactic, subtechniques=subtechniques)
        if techniques:
            return techniques
    except Exception as e:
        logger.warning(f"Database mitre techniques query notice: {e}")

    # Fallback
    res = list(SAMPLE_TECHNIQUES)
    if subtechniques is not None:
        res = [t for t in res if t["is_subtechnique"] == subtechniques]
    if tactic and tactic.lower() != "all":
        res = [t for t in res if any(tactic.lower() == tac.lower() for tac in t["tactics"])]
    return res


@router.get("/tactics", response_model=List[MitreTacticRead])
async def get_mitre_tactics(db: AsyncSession = Depends(get_db)):
    """Returns verified enterprise MITRE ATT&CK tactics with descriptions."""
    try:
        tactics = await MitreService.get_all_tactics(db)
        if tactics:
            return tactics
    except Exception as e:
        logger.warning(f"Database mitre tactics query notice: {e}")

    return SAMPLE_TACTICS


@router.get("/techniques/{technique_id}", response_model=MitreTechniqueRead)
async def get_mitre_technique(technique_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve details for a specific verified MITRE technique or sub-technique."""
    try:
        technique = await MitreService.get_technique_by_id(db, technique_id)
        if technique:
            return technique
    except Exception as e:
        logger.warning(f"Database mitre technique query notice: {e}")

    for t in SAMPLE_TECHNIQUES:
        if t["id"].lower() == technique_id.lower():
            return t

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"error": {"code": "NOT_FOUND", "message": f"Technique {technique_id} not found in verified ATT&CK catalog"}},
    )
