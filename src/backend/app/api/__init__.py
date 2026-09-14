"""API Router aggregation module"""

from fastapi import APIRouter
from app.api.auth import router as auth_router
from app.api.dashboard import router as dashboard_router
from app.api.alerts import router as alerts_router
from app.api.threats import router as threats_router
from app.api.investigations import router as investigations_router
from app.api.intelligence import router as intelligence_router
from app.api.mitre import router as mitre_router
from app.api.bluf import router as bluf_router
from app.api.data_sources import router as data_sources_router
from app.api.ai import router as ai_router

api_router = APIRouter()

api_router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
api_router.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(alerts_router, prefix="/alerts", tags=["Alerts"])
api_router.include_router(threats_router, prefix="/threats", tags=["Threats"])
api_router.include_router(threats_router, prefix="/incidents", tags=["Incidents (Frontend Alias)"])
api_router.include_router(investigations_router, prefix="/investigations", tags=["Investigations"])
api_router.include_router(intelligence_router, prefix="/intelligence", tags=["Threat Intelligence"])
api_router.include_router(mitre_router, prefix="/mitre", tags=["MITRE ATT&CK"])
api_router.include_router(bluf_router, prefix="/bluf", tags=["BLUF Briefs"])
api_router.include_router(bluf_router, prefix="/briefs", tags=["BLUF Briefs (Frontend Alias)"])
api_router.include_router(data_sources_router, prefix="/data-sources", tags=["Data Sources"])
api_router.include_router(ai_router, prefix="/ai", tags=["AI Analysis"])
