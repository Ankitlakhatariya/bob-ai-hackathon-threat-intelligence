import pytest
from httpx import AsyncClient
from app.services.threat_scoring import ThreatScoringEngine
from app.models.alert import AlertSeverity
from app.core.permissions import UserRole, Permission, get_permissions_for_role
from app.core.security import verify_password, get_password_hash, create_access_token


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
    assert "permissions" in data["user"]


@pytest.mark.asyncio
async def test_auth_registration_and_login_flow(async_client: AsyncClient):
    """Test complete register -> login -> me -> refresh flow."""
    test_email = "test-analyst-soc@threatlens.io"
    test_password = "SecurePassword123!"

    # 1. Register
    reg_response = await async_client.post(
        "/api/v1/auth/register",
        json={
            "email": test_email,
            "password": test_password,
            "full_name": "Test SOC Analyst",
            "role": "ANALYST",
        },
    )
    assert reg_response.status_code in [201, 400]  # 400 if already registered from previous run

    # 2. Login with correct password
    login_response = await async_client.post(
        "/api/v1/auth/login",
        json={"email": test_email, "password": test_password},
    )
    assert login_response.status_code == 200
    login_data = login_response.json()
    assert "access_token" in login_data
    assert "refresh_token" in login_data
    access_token = login_data["access_token"]
    refresh_token = login_data["refresh_token"]

    # 3. Access /auth/me with Bearer token
    me_response = await async_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_response.status_code == 200
    me_data = me_response.json()
    assert me_data["user"]["email"] == test_email
    assert me_data["role"] == "ANALYST"
    assert "alerts:read" in me_data["user"]["permissions"]

    # 4. Exchange refresh token
    refresh_response = await async_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_response.status_code == 200
    assert "access_token" in refresh_response.json()


@pytest.mark.asyncio
async def test_auth_invalid_login(async_client: AsyncClient):
    """Test that login rejects invalid passwords."""
    response = await async_client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent@threatlens.io", "password": "WrongPassword!"},
    )
    assert response.status_code == 401
    assert "error" in response.json()


@pytest.mark.asyncio
async def test_role_permissions_matrix():
    """Verify role permissions hierarchy."""
    admin_perms = get_permissions_for_role(UserRole.ADMIN)
    analyst_perms = get_permissions_for_role(UserRole.ANALYST)
    commander_perms = get_permissions_for_role(UserRole.COMMANDER)
    viewer_perms = get_permissions_for_role(UserRole.VIEWER)

    # Admin has users:manage and data_sources:manage
    assert Permission.USERS_MANAGE in admin_perms
    assert Permission.DATA_SOURCES_MANAGE in admin_perms

    # Analyst can write alerts and run correlation, but cannot manage users
    assert Permission.ALERTS_WRITE in analyst_perms
    assert Permission.CORRELATION_RUN in analyst_perms
    assert Permission.USERS_MANAGE not in analyst_perms

    # Commander and Viewer CANNOT write alerts
    assert Permission.ALERTS_WRITE not in commander_perms
    assert Permission.ALERTS_WRITE not in viewer_perms

    # Commander CAN view BLUF reports
    assert Permission.BLUF_READ in commander_perms


def test_password_hashing():
    """Test PBKDF2 salt:hash password hashing and verification."""
    password = "SuperSecretPassword123"
    hashed = get_password_hash(password)
    assert ":" in hashed
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


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
async def test_alerts_trend(async_client: AsyncClient):
    """Test alert trend for 24h window."""
    response = await async_client.get("/api/v1/alerts/trend?range=24h")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0


@pytest.mark.asyncio
async def test_mitre_techniques(async_client: AsyncClient):
    """Test MITRE ATT&CK techniques catalogue."""
    response = await async_client.get("/api/v1/mitre/techniques")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0


@pytest.mark.asyncio
async def test_bluf_briefs_map(async_client: AsyncClient):
    """Test BLUF briefs mapping endpoint for incident cards."""
    response = await async_client.get("/api/v1/bluf")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, dict)
