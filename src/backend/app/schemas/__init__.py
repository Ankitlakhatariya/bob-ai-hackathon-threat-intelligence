"""Pydantic schemas for request validation and response serialization"""

from app.schemas.auth import UserProfile, AuthResponse
from app.schemas.alert import AlertRead, AlertCreate, AlertUpdate, AlertBulkIngestResponse, TrendPointResponse
from app.schemas.threat import ThreatRead, ThreatCreate, ThreatUpdate, ThreatTimelineEvent
from app.schemas.correlation import CorrelationRead, CorrelationResult
from app.schemas.intelligence import IndicatorRead, IndicatorCreate, IndicatorLookupResponse
from app.schemas.investigation import InvestigationRead, InvestigationCreate, InvestigationUpdate, InvestigationNoteCreate
from app.schemas.mitre import MitreTacticRead, MitreTechniqueRead, ThreatMitreRead
from app.schemas.bluf import BlufReportRead, BlufGenerateRequest
from app.schemas.dashboard import DashboardOverview, SeverityDistributionItem, SystemStatusItem
from app.schemas.data_source import DataSourceRead, DataSourceCreate, DataSourceUpdate

__all__ = [
    "UserProfile",
    "AuthResponse",
    "AlertRead",
    "AlertCreate",
    "AlertUpdate",
    "AlertBulkIngestResponse",
    "TrendPointResponse",
    "ThreatRead",
    "ThreatCreate",
    "ThreatUpdate",
    "ThreatTimelineEvent",
    "CorrelationRead",
    "CorrelationResult",
    "IndicatorRead",
    "IndicatorCreate",
    "IndicatorLookupResponse",
    "InvestigationRead",
    "InvestigationCreate",
    "InvestigationUpdate",
    "InvestigationNoteCreate",
    "MitreTacticRead",
    "MitreTechniqueRead",
    "ThreatMitreRead",
    "BlufReportRead",
    "BlufGenerateRequest",
    "DashboardOverview",
    "SeverityDistributionItem",
    "SystemStatusItem",
    "DataSourceRead",
    "DataSourceCreate",
    "DataSourceUpdate",
]
