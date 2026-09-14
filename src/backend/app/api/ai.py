from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.session import get_db
from app.models.threat import Threat
from app.models.alert import Alert
from app.models.llm_analysis import LLMAnalysis
from app.models.bluf import BlufReport
from app.services.llm_service import OpenAIThreatAnalysisService
from app.schemas.llm import ThreatAnalysisResponse
from app.schemas.bluf import BlufReportCreate, BlufReportResponse
from app.core.rate_limit import llm_rate_limiter

router = APIRouter()
llm_service = OpenAIThreatAnalysisService()


@router.post("/analyze-threat/{threat_id}", response_model=Dict[str, Any], dependencies=[Depends(llm_rate_limiter)])
async def analyze_threat(threat_id: str, db: AsyncSession = Depends(get_db)):
    """
    Generate an LLM analysis of a threat and its associated alerts.
    """
    if not llm_service.is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "AI_NOT_CONFIGURED",
                "message": "AI analysis service is not configured"
            }
        )

    # 1. Load Threat
    threat_query = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = threat_query.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    # 2. Load Correlated Alerts
    alerts_query = await db.execute(select(Alert).where(Alert.related_threat_id == threat_id))
    alerts = alerts_query.scalars().all()

    # 3. Build Context
    threat_context = {
        "threat": {
            "id": threat.id,
            "title": threat.title,
            "description": threat.description,
            "severity": threat.severity,
            "risk_score": threat.risk_score,
            "confidence": threat.confidence,
            "affected_assets": threat.affected_assets,
            "mitre_techniques": threat.mitre_techniques
        },
        "alerts": [
            {
                "id": a.id,
                "title": a.title,
                "description": a.description,
                "severity": a.severity,
                "source": a.source,
                "indicators": a.indicators
            } for a in alerts
        ]
    }

    try:
        # 4. Call LLM
        analysis: ThreatAnalysisResponse = await llm_service.analyze_threat(threat_context)

        # 5. Save LLMAnalysis
        db_analysis = LLMAnalysis(
            threat_id=threat.id,
            model=llm_service.model,
            prompt_version="v1",
            output=analysis.model_dump(),
            confidence=analysis.confidence
        )
        db.add(db_analysis)
        await db.commit()
        await db.refresh(db_analysis)

        return {
            "id": db_analysis.id,
            "threat_id": db_analysis.threat_id,
            "model": db_analysis.model,
            "prompt_version": db_analysis.prompt_version,
            "generated_at": db_analysis.generated_at.isoformat(),
            "analysis": db_analysis.output
        }

    except ValueError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"LLM Service Error: {str(e)}")


@router.post("/generate-bluf/{threat_id}", response_model=BlufReportResponse, dependencies=[Depends(llm_rate_limiter)])
async def generate_bluf(threat_id: str, db: AsyncSession = Depends(get_db)):
    """
    Generate a BLUF (Bottom Line Up Front) report using the LLM.
    """
    if not llm_service.is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "AI_NOT_CONFIGURED",
                "message": "AI analysis service is not configured"
            }
        )

    # 1. Get threat context
    threat_query = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = threat_query.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    try:
        # 2. We can call the same analyze_threat endpoint to get the BLUF component
        # Alternatively, we just extract the BLUF from the full analysis prompt
        threat_context = {
            "threat_id": threat.id,
            "title": threat.title,
            "summary": threat.summary,
            "severity": threat.severity,
            "risk_score": threat.risk_score
        }
        analysis: ThreatAnalysisResponse = await llm_service.analyze_threat(threat_context)

        # 3. Update or create BLUF report
        bluf_query = await db.execute(select(BlufReport).where(BlufReport.threat_id == threat_id))
        report = bluf_query.scalar_one_or_none()

        if not report:
            report = BlufReport(threat_id=threat_id)
            db.add(report)

        report.bottom_line = analysis.bluf
        report.impact = "Generated by AI: " + ", ".join(threat.affected_assets)
        report.key_evidence = "\\n".join(analysis.evidence)
        report.recommended_focus = "\\n".join(analysis.recommended_investigation_focus)

        await db.commit()
        await db.refresh(report)
        return report

    except Exception as e:
        raise HTTPException(status_code=502, detail=f"LLM Service Error: {str(e)}")
