import pytest
from httpx import AsyncClient
from app.services.threat_scoring import ThreatScoringEngine
from app.models.alert import AlertSeverity
from app.core.security import jwt_validator


@pytest.mark.asyncio
async def test_health_endpoint(async_client: AsyncClient):
    """Test standard GET /health endpoint."""
    response = await async_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["status"] in ["healthy", "degraded"]


@pytest.mark.asyncio
async def test_api_v1_health_endpoint(async_client: AsyncClient):
    """Test versioned GET /api/v1/health endpoint."""
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data


@pytest.mark.asyncio
async def test_auth_me_demo_fallback(async_client: AsyncClient):
    """Test GET /api/v1/auth/me returns demo profile when no bearer token is passed."""
    response = await async_client.get("/api/v1/auth/me")
    assert response.status_code == 200
    data = response.json()
    assert "user" in data
    assert data["role"] in ["ANALYST", "ADMIN"]
    assert "email" in data["user"]


@pytest.mark.asyncio
async def test_dashboard_overview(async_client: AsyncClient):
    """Test dashboard overview statistics."""
    response = await async_client.get("/api/v1/dashboard/overview")
    assert response.status_code == 200
    data = response.json()
    assert "totalOpen" in data
    assert "critical" in data
    assert "incidentCount" in data
    assert "falsePositiveReview" in data


@pytest.mark.asyncio
async def test_dashboard_system_status(async_client: AsyncClient):
    """Test telemetry feeds health monitoring."""
    response = await async_client.get("/api/v1/dashboard/system-status")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if len(data) > 0:
        assert "id" in data[0]
        assert "health" in data[0]


@pytest.mark.asyncio
async def test_alerts_trend(async_client: AsyncClient):
    """Test alert trend for 24h, 7d, 30d windows."""
    for window in ["24h", "7d", "30d"]:
        response = await async_client.get(f"/api/v1/alerts/trend?range={window}")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        assert "label" in data[0]
        assert "alerts" in data[0]
        assert "incidents" in data[0]


@pytest.mark.asyncio
async def test_mitre_techniques(async_client: AsyncClient):
    """Test MITRE ATT&CK techniques catalogue."""
    response = await async_client.get("/api/v1/mitre/techniques")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0
    assert "id" in data[0]
    assert "tactics" in data[0]


@pytest.mark.asyncio
async def test_mitre_tactics(async_client: AsyncClient):
    """Test MITRE ATT&CK tactics list."""
    response = await async_client.get("/api/v1/mitre/tactics")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert "Initial Access" in data
    assert "Execution" in data


@pytest.mark.asyncio
async def test_bluf_briefs_map(async_client: AsyncClient):
    """Test BLUF briefs mapping endpoint for incident cards."""
    response = await async_client.get("/api/v1/bluf")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, dict)
    if "INC-1001" in data:
        brief = data["INC-1001"]
        assert "bottomLine" in brief
        assert "impact" in brief
        assert "keyEvidence" in brief
        assert "recommendedFocus" in brief


def test_threat_scoring_engine():
    """Unit test for deterministic risk scoring logic."""
    # Critical severity with indicators and mitre technique
    score = ThreatScoringEngine.calculate_alert_risk(
        severity=AlertSeverity.CRITICAL,
        indicators_count=2,
        mitre_count=1,
        is_correlated=True,
    )
    assert 75 <= score <= 100
    assert ThreatScoringEngine.get_priority_band(score) == "CRITICAL"

    # Low severity without extra factors
    score_low = ThreatScoringEngine.calculate_alert_risk(
        severity=AlertSeverity.LOW,
        indicators_count=0,
        mitre_count=0,
        is_correlated=False,
    )
    assert score_low <= 40
    assert ThreatScoringEngine.get_priority_band(score_low) in ["LOW", "MEDIUM"]


def test_jwt_validator_unverified():
    """Test decoding token without secret in local development mode."""
    import jwt
    token = jwt.encode({"sub": "user-123", "email": "test@soc.com"}, "key", algorithm="HS256")
    claims = jwt_validator.verify_token(token)
    assert claims["sub"] == "user-123"
    assert claims["email"] == "test@soc.com"
