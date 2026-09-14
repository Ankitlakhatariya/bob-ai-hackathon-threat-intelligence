from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.dependencies import get_db
from app.models.mitre import MitreTactic, MitreTechnique
from app.schemas.mitre import MitreTacticRead, MitreTechniqueRead
from app.services.mitre_service import MitreService

router = APIRouter()


@router.get("", response_model=List[MitreTechniqueRead])
@router.get("/techniques", response_model=List[MitreTechniqueRead])
async def get_mitre_techniques(
    tactic: Optional[str] = Query(None, description="Initial Access, Execution, etc."),
    db: AsyncSession = Depends(get_db),
):
    """Returns verified MITRE ATT&CK techniques catalogue."""
    return await MitreService.get_all_techniques(db, tactic)


@router.get("/tactics", response_model=List[str])
async def get_mitre_tactics(db: AsyncSession = Depends(get_db)):
    """Returns all 10 core enterprise tactics present in the platform."""
    return [
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Lateral Movement",
        "Command and Control",
        "Exfiltration",
        "Impact",
    ]


@router.get("/techniques/{technique_id}", response_model=MitreTechniqueRead)
async def get_mitre_technique(technique_id: str, db: AsyncSession = Depends(get_db)):
    technique = await MitreService.get_technique_by_id(db, technique_id)
    if not technique:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "NOT_FOUND", "message": f"Technique {technique_id} not found"}},
        )
    return technique
