from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.dependencies import get_db
from app.models.mitre import MitreTactic, MitreTechnique
from app.schemas.mitre import MitreTacticRead, MitreTechniqueRead
from app.services.mitre_service import MitreService

router = APIRouter()


@router.get("", response_model=List[MitreTechniqueRead])
@router.get("/techniques", response_model=List[MitreTechniqueRead])
async def get_mitre_techniques(
    tactic: Optional[str] = Query(None, description="Initial Access, Execution, etc."),
    subtechniques: Optional[bool] = Query(None, description="Filter by sub-technique status"),
    db: AsyncSession = Depends(get_db),
):
    """Returns verified MITRE ATT&CK techniques and sub-techniques catalogue."""
    return await MitreService.get_all_techniques(db, tactic=tactic, subtechniques=subtechniques)


@router.get("/tactics", response_model=List[MitreTacticRead])
async def get_mitre_tactics(db: AsyncSession = Depends(get_db)):
    """Returns verified enterprise MITRE ATT&CK tactics with descriptions."""
    return await MitreService.get_all_tactics(db)


@router.get("/techniques/{technique_id}", response_model=MitreTechniqueRead)
async def get_mitre_technique(technique_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieve details for a specific verified MITRE technique or sub-technique."""
    technique = await MitreService.get_technique_by_id(db, technique_id)
    if not technique:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": f"Technique {technique_id} not found in verified ATT&CK catalog"}},
        )
    return technique
