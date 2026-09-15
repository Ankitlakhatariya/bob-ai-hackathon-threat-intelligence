import time
from contextlib import asynccontextmanager
from typing import Dict, Any
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings
from app.core.logging import setup_logging, logger
from app.core.middleware import RequestSizeLimitMiddleware, SecurityHeadersMiddleware
from app.api import api_router
from app.database.session import check_database_connection, AsyncSessionLocal
from app.database.database import Base
from app.database.session import async_engine
from app.models.alert import Alert, AlertSeverity, AlertStatus, AlertSource
from app.models.threat import Threat, ThreatSeverity, ThreatStatus
from app.models.data_source import DataSource, DataSourceStatus
from app.models.mitre import MitreTechnique
from app.models.bluf import BlufReport
from app.services.mitre_service import STANDARD_TECHNIQUES
from app.services.bluf_service import STANDARD_BRIEFS
from sqlalchemy import select, func


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    setup_logging()
    logger.info(f"Starting {settings.PROJECT_NAME} in [{settings.ENVIRONMENT}] mode...")

    # Ensure tables exist in database automatically
    try:
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables initialized successfully via SQLAlchemy metadata.")
    except Exception as e:
        logger.warning(f"Metadata create_all notice: {e}")

    # Seed baseline demo alerts & threats if database is blank
    try:
        async with AsyncSessionLocal() as db:
            alert_count_res = await db.execute(select(func.count(Alert.id)))
            alert_count = alert_count_res.scalar() or 0

            if alert_count == 0:
                logger.info("Database is empty. Pre-seeding standard demo dataset for frontend compatibility...")

                # 1. Standard MITRE
                for tech_data in STANDARD_TECHNIQUES:
                    tech = MitreTechnique(**tech_data)
                    db.add(tech)

                # 2. Standard Data Sources
                default_sources = [
                    DataSource(id="siem", name="SIEM ingestion", detail="QRadar · healthy · 12s lag", health=DataSourceStatus.HEALTHY),
                    DataSource(id="edr", name="Endpoint detection", detail="All agents reporting", health=DataSourceStatus.HEALTHY),
                    DataSource(id="network", name="Network sensors", detail="Segment 4 degraded · 1 sensor offline", health=DataSourceStatus.DEGRADED),
                    DataSource(id="threatintel", name="Threat intel feed", detail="Last update 3 min ago", health=DataSourceStatus.HEALTHY),
                    DataSource(id="correlation", name="Correlation engine", detail="Jobs running normally", health=DataSourceStatus.OPERATIONAL),
                ]
                for s in default_sources:
                    db.add(s)

                # 3. Standard Threats (Incidents)
                threats_data = [
                    Threat(
                        id="INC-1001",
                        title="Malware delivery via email campaign",
                        summary="Correlated alerts reveal an initial spearphishing attachment that executed a macro, followed by anomalous PowerShell execution and beaconing to an external IP. Highly consistent with an initial access / command-and-control sequence.",
                        explanation="These alerts share the same delivery campaign, targeting user accounts across the north office. Execution indicators align with a unified malware staging chain.",
                        severity=ThreatSeverity.CRITICAL,
                        status=ThreatStatus.INVESTIGATING,
                        confidence=82,
                        alert_ids=["ALERT-2033", "ALERT-2036", "ALERT-2031"],
                        mitre_techniques=["T1204.001", "T1566.001", "T1204.002", "T1190"],
                    ),
                    Threat(
                        id="INC-1002",
                        title="Border gateway brute force and VPN access",
                        summary="A high volume of failed authentication events on the external VPN gateway was followed within 25 minutes by a successful login from an anomalous geographic IP. Network traffic indicates reconnaissance of internal services.",
                        explanation="Repeated authentication failures against the external VPN gateway culminated in a single successful session from the same anomalous source IP.",
                        severity=ThreatSeverity.HIGH,
                        status=ThreatStatus.INVESTIGATING,
                        confidence=74,
                        alert_ids=["ALERT-2032", "ALERT-2034", "ALERT-2037"],
                        mitre_techniques=["T1110", "T1078"],
                    ),
                    Threat(
                        id="INC-1003",
                        title="Privilege escalation and credential dumping",
                        summary="Alerts from endpoint sensors indicate suspicious LSASS memory access on a backup domain controller, followed by atypical Kerberos ticket requests consistent with credential harvesting in progress.",
                        explanation="LSASS memory access on a sensitive controller followed by abnormal Kerberos ticket requests indicates a coordinated credential-dumping attempt.",
                        severity=ThreatSeverity.CRITICAL,
                        status=ThreatStatus.ACTIVE,
                        confidence=91,
                        alert_ids=["ALERT-2041", "ALERT-2039", "ALERT-2040"],
                        mitre_techniques=["T1003", "T1078", "T1021.002"],
                    ),
                    Threat(
                        id="INC-1004",
                        title="Data staging on internal file share",
                        summary="Unusual file archiving activity on an internal departmental share paired with an abnormal volume of outbound HTTPS requests. Possible exfiltration staging detected by endpoint and network sensors.",
                        explanation="An archive creation utility was executed on a share holding confidential files, immediately followed by elevated encrypted outbound traffic.",
                        severity=ThreatSeverity.MEDIUM,
                        status=ThreatStatus.RESOLVED,
                        confidence=68,
                        alert_ids=["ALERT-2042", "ALERT-2043", "ALERT-2044"],
                        mitre_techniques=["T1041", "T1486"],
                    ),
                ]
                for t in threats_data:
                    db.add(t)

                # 4. Standard BLUF Briefs
                for t_id, b_data in STANDARD_BRIEFS.items():
                    report = BlufReport(
                        threat_id=t_id,
                        bottom_line=b_data["bottom_line"],
                        impact=b_data["impact"],
                        key_evidence=b_data["key_evidence"],
                        recommended_focus=b_data["recommended_focus"],
                    )
                    db.add(report)

                # 5. Standard 14 Alerts
                demo_alerts = [
                    Alert(
                        id="ALERT-2041",
                        team_id="t-soc-north",
                        title="Potential credential theft via sensitive-account access",
                        description="Anomalous access pattern detected on privileged administrator account outside core operational hours.",
                        source=AlertSource.EDR,
                        source_label="EDR Endpoint Agent",
                        severity=AlertSeverity.HIGH,
                        status=AlertStatus.INVESTIGATING,
                        risk_score=78,
                        related_threat_id="INC-1003",
                        mitre_techniques=["T1003"],
                        indicators=["198.51.100.7", "svc-backup.example"],
                    ),
                    Alert(
                        id="ALERT-2040",
                        team_id="t-soc-north",
                        title="Suspicious SMB share enumeration across DC controllers",
                        description="Rapid succession of SMB IPC$ sessions and directory listing attempts across domain controllers.",
                        source=AlertSource.NETWORK_SENSOR,
                        source_label="Network Sensor",
                        severity=AlertSeverity.HIGH,
                        status=AlertStatus.INVESTIGATING,
                        risk_score=72,
                        related_threat_id="INC-1003",
                        mitre_techniques=["T1021.002"],
                        indicators=["198.51.100.8", "IPC$"],
                    ),
                    Alert(
                        id="ALERT-2039",
                        team_id="t-soc-north",
                        title="Atypical Kerberos ticket request volume",
                        description="High-frequency TGS requests indicating potential Kerberoasting attack pattern.",
                        source=AlertSource.SIEM,
                        source_label="SIEM",
                        severity=AlertSeverity.CRITICAL,
                        status=AlertStatus.INVESTIGATING,
                        risk_score=88,
                        related_threat_id="INC-1003",
                        mitre_techniques=["T1078"],
                        indicators=["krbtgt", "198.51.100.9"],
                    ),
                    Alert(
                        id="ALERT-2038",
                        team_id="t-soc-north",
                        title="Suspicious outbound beacon pattern to unclassified IP",
                        description="Periodic HTTP/S requests with fixed interval and small payload matching command-and-control beaconing profile.",
                        source=AlertSource.NETWORK_SENSOR,
                        source_label="Network Sensor",
                        severity=AlertSeverity.CRITICAL,
                        status=AlertStatus.OPEN,
                        risk_score=85,
                        related_threat_id=None,
                        mitre_techniques=["T1071.001", "T1573.002"],
                        indicators=["203.0.113.42", "c2-checkin.example"],
                    ),
                    Alert(
                        id="ALERT-2037",
                        team_id="t-soc-north",
                        title="Unusual outbound SSH session initiated from staging host",
                        description="Outbound encrypted connection initiated from a staging host to an external address not present in baseline.",
                        source=AlertSource.SIEM,
                        source_label="SIEM",
                        severity=AlertSeverity.MEDIUM,
                        status=AlertStatus.INVESTIGATING,
                        risk_score=54,
                        related_threat_id="INC-1002",
                        mitre_techniques=["T1021.002"],
                        indicators=["203.0.113.88", "staging-02.corp"],
                    ),
                    Alert(
                        id="ALERT-2036",
                        team_id="t-soc-north",
                        title="Obfuscated PowerShell command execution on workstation",
                        description="Base64-encoded command line with download cradle syntax executed by standard office user context.",
                        source=AlertSource.EDR,
                        source_label="EDR Endpoint Agent",
                        severity=AlertSeverity.CRITICAL,
                        status=AlertStatus.INVESTIGATING,
                        risk_score=82,
                        related_threat_id="INC-1001",
                        mitre_techniques=["T1059.001", "T1204.002"],
                        indicators=["powershell.exe", "EncodedCommand", "ws-042"],
                    ),
                    Alert(
                        id="ALERT-2035",
                        team_id="t-soc-north",
                        title="Anomalous administrative login from previously unseen subnet",
                        description="Single successful interactive logon to cloud console from an IP range never previously associated with this user.",
                        source=AlertSource.SIEM,
                        source_label="SIEM",
                        severity=AlertSeverity.MEDIUM,
                        status=AlertStatus.OPEN,
                        risk_score=48,
                        related_threat_id=None,
                        mitre_techniques=["T1078"],
                        indicators=["192.0.2.19", "admin.clouddemo"],
                    ),
                    Alert(
                        id="ALERT-2034",
                        team_id="t-soc-north",
                        title="Single successful authentication after repeated VPN failures",
                        description="Successful authentication followed immediately after multiple invalid credential attempts from the same source IP.",
                        source=AlertSource.SIEM,
                        source_label="SIEM",
                        severity=AlertSeverity.HIGH,
                        status=AlertStatus.INVESTIGATING,
                        risk_score=68,
                        related_threat_id="INC-1002",
                        mitre_techniques=["T1078", "T1110"],
                        indicators=["203.0.113.88", "vpn-gw-01"],
                    ),
                    Alert(
                        id="ALERT-2033",
                        team_id="t-soc-north",
                        title="Malicious Office macro executed from email attachment",
                        description="Endpoint blocked macro attempting to write an executable to temp directory following email download.",
                        source=AlertSource.EDR,
                        source_label="EDR Endpoint Agent",
                        severity=AlertSeverity.HIGH,
                        status=AlertStatus.INVESTIGATING,
                        risk_score=75,
                        related_threat_id="INC-1001",
                        mitre_techniques=["T1566.001", "T1204.002"],
                        indicators=["invoice_sep26.xlsm", "ws-042"],
                    ),
                    Alert(
                        id="ALERT-2032",
                        team_id="t-soc-north",
                        title="High-rate password spraying against external VPN gateway",
                        description="More than 450 authentication attempts observed within 15 minutes targeting multiple user identifiers.",
                        source=AlertSource.NETWORK_SENSOR,
                        source_label="Network Sensor",
                        severity=AlertSeverity.HIGH,
                        status=AlertStatus.INVESTIGATING,
                        risk_score=65,
                        related_threat_id="INC-1002",
                        mitre_techniques=["T1110"],
                        indicators=["203.0.113.88", "vpn-gw-01"],
                    ),
                    Alert(
                        id="ALERT-2031",
                        team_id="t-soc-north",
                        title="Known adversary infrastructure contacted over HTTPS",
                        description="Network connection to IP identified in commercial threat feed as Cobalt Strike staging infrastructure.",
                        source=AlertSource.THREAT_FEED,
                        source_label="Threat Intel Feed",
                        severity=AlertSeverity.HIGH,
                        status=AlertStatus.INVESTIGATING,
                        risk_score=71,
                        related_threat_id="INC-1001",
                        mitre_techniques=["T1071.001"],
                        indicators=["198.51.100.23", "feed-adversary-set"],
                    ),
                    Alert(
                        id="ALERT-2030",
                        team_id="t-soc-north",
                        title="Scheduled task created with abnormal execution target",
                        description="Persistence attempt detected: scheduled task configured to execute script from user temporary folder.",
                        source=AlertSource.EDR,
                        source_label="EDR Endpoint Agent",
                        severity=AlertSeverity.MEDIUM,
                        status=AlertStatus.OPEN,
                        risk_score=52,
                        related_threat_id=None,
                        mitre_techniques=["T1053.005"],
                        indicators=["schtasks.exe", "UpdateCheck_Daily"],
                    ),
                    Alert(
                        id="ALERT-2029",
                        team_id="t-soc-north",
                        title="Port scan sweep across internal server subnet",
                        description="SYN scan targeting ports 22, 445, 3389, and 8080 across 64 consecutive hosts.",
                        source=AlertSource.NETWORK_SENSOR,
                        source_label="Network Sensor",
                        severity=AlertSeverity.LOW,
                        status=AlertStatus.OPEN,
                        risk_score=28,
                        related_threat_id=None,
                        mitre_techniques=[],
                        indicators=["10.0.4.15", "10.0.4.0/24"],
                    ),
                    Alert(
                        id="ALERT-2028",
                        team_id="t-soc-north",
                        title="Automated vulnerability scanner signature detected",
                        description="Repeated HTTP GET requests with known scanner headers matching internal scheduled penetration testing schedule.",
                        source=AlertSource.SIEM,
                        source_label="SIEM",
                        severity=AlertSeverity.LOW,
                        status=AlertStatus.FALSE_POSITIVE,
                        risk_score=15,
                        related_threat_id=None,
                        mitre_techniques=[],
                        indicators=["10.0.1.100", "scanner-nikto-sig"],
                    ),
                ]

                for a in demo_alerts:
                    db.add(a)

                await db.commit()
                logger.info("Successfully seeded standard 14 demo alerts and 4 threat campaigns.")
    except Exception as e:
        logger.error(f"Startup seeding check notice: {e}")

    yield

    logger.info(f"Shutting down {settings.PROJECT_NAME}...")


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Production-ready FastAPI backend for Threat Intelligence Correlation and Alert Prioritization",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# Security Middlewares
app.add_middleware(RequestSizeLimitMiddleware, max_body_size=2 * 1024 * 1024) # 2MB limit
app.add_middleware(SecurityHeadersMiddleware)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Structured Request Logging Middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    logger.info(
        f"{request.method} {request.url.path} - Status: {response.status_code} - Completed in {duration:.3f}s"
    )
    return response


# Global Exception Handlers for consistent API errors
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    detail = exc.detail
    if isinstance(detail, dict):
        if "error" in detail:
            error_body = detail
        else:
            error_body = {"error": detail}
    else:
        error_body = {
            "error": {
                "code": f"HTTP_{exc.status_code}",
                "message": str(detail),
            }
        }
    return JSONResponse(status_code=exc.status_code, content=error_body, headers=getattr(exc, "headers", None))


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Invalid request parameters",
                "details": exc.errors(),
            }
        },
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled system exception on {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred. Please try again later.",
            }
        },
    )


# Health check endpoints
@app.get("/health", tags=["Health"])
@app.get("/api/v1/health", tags=["Health"])
async def health_check():
    """System health check endpoint."""
    db_ok = await check_database_connection()
    return {
        "status": "healthy" if db_ok else "degraded",
        "database": "connected" if db_ok else "disconnected",
        "service": settings.PROJECT_NAME,
        "environment": settings.ENVIRONMENT,
    }


# Mount API Router
app.include_router(api_router, prefix=settings.API_V1_STR)

# Also mount alert / incident aliases directly at root /api/ for frontend mockApi.ts compatibility
app.include_router(api_router, prefix="/api")
