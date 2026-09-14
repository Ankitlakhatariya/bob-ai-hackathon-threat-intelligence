import pytest
import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch

from app.main import app
from app.models.user import User, UserRole
from app.models.alert import Alert, AlertSeverity, AlertSource, AlertStatus
from app.models.threat import Threat, ThreatSeverity, ThreatStatus
from app.models.investigation import Investigation, InvestigationStatus, InvestigationPriority


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture
def db_session():
    """
    Provides an AsyncMock of the database session.
    A real PostgreSQL test database is preferred but impossible in this environment 
    due to the lack of docker/psql and failing dependency resolution for asyncpg.
    """
    mock_session = AsyncMock()
    mock_session.execute = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_session.refresh = AsyncMock()
    return mock_session


# --- User Fixtures ---

@pytest.fixture
def mock_admin_user():
    return User(
        id=uuid.uuid4(),
        email="admin@threatlens.io",
        full_name="Admin User",
        role=UserRole.ADMIN,
        is_active=True
    )

@pytest.fixture
def mock_analyst_user():
    return User(
        id=uuid.uuid4(),
        email="analyst@threatlens.io",
        full_name="Analyst User",
        role=UserRole.ANALYST,
        is_active=True
    )

@pytest.fixture
def mock_commander_user():
    return User(
        id=uuid.uuid4(),
        email="commander@threatlens.io",
        full_name="Commander User",
        role=UserRole.COMMANDER,
        is_active=True
    )

@pytest.fixture
def mock_viewer_user():
    return User(
        id=uuid.uuid4(),
        email="viewer@threatlens.io",
        full_name="Viewer User",
        role=UserRole.VIEWER,
        is_active=True
    )


# --- Telemetry Fixtures ---

@pytest.fixture
def mock_alert():
    return Alert(
        id=f"ALERT-{uuid.uuid4()}",
        source=AlertSource.EDR,
        title="Suspicious Process Execution",
        description="powershell.exe downloading payload",
        severity=AlertSeverity.HIGH,
        status=AlertStatus.OPEN,
        risk_score=75,
        timestamp=datetime.now(timezone.utc),
        hostname="WORKSTATION-01",
        username="jdoe",
        process_name="powershell.exe",
        indicators=["198.51.100.12"]
    )

@pytest.fixture
def mock_threat(mock_alert):
    return Threat(
        id=f"INC-{uuid.uuid4()}",
        threat_id="INC-1001",
        title="Campaign: Suspicious Process Execution",
        severity=ThreatSeverity.HIGH,
        status=ThreatStatus.ACTIVE,
        risk_score=75,
        confidence=60,
        alert_count=1,
        affected_assets=["WORKSTATION-01"],
        first_seen=mock_alert.timestamp,
        last_seen=mock_alert.timestamp,
        alert_ids=[mock_alert.id],
        mitre_techniques=["T1059.001"]
    )

@pytest.fixture
def mock_investigation(mock_threat):
    return Investigation(
        id=uuid.uuid4(),
        threat_id=mock_threat.id,
        title="Investigating PowerShell Activity",
        status=InvestigationStatus.OPEN,
        priority=InvestigationPriority.P2,
        assigned_to="analyst@threatlens.io",
        created_at=datetime.now(timezone.utc)
    )

# --- Service Mocks ---

@pytest.fixture(autouse=True)
def mock_llm_service():
    """Automatically mock OpenAI interactions to prevent real network calls."""
    with patch("app.api.ai.llm_service.analyze_threat", new_callable=AsyncMock) as mock_analyze:
        with patch("app.api.ai.llm_service.is_configured", return_value=True):
            yield mock_analyze

@pytest.fixture(autouse=True)
def mock_threat_intel():
    """Automatically mock External Threat Intel to prevent real network calls."""
    with patch("app.services.intelligence.provider.ExternalThreatIntelProvider.lookup", new_callable=AsyncMock) as mock_lookup:
        yield mock_lookup
