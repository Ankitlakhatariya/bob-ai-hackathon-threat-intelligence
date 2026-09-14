import pytest
from httpx import AsyncClient
from datetime import datetime, timezone, timedelta
from app.models.alert import Alert, AlertSeverity, AlertSource, AlertStatus
from app.services.correlation import CorrelationEngine


def test_deterministic_correlation_pair_evaluation():
    """Verify deterministic rule-based evaluation between related alerts."""
    now = datetime.now(timezone.utc)

    # Alert A: Suspicious login
    alert_a = Alert(
        id="ALERT-TEST-01",
        title="Suspicious SSH Login",
        description="SSH login from uncommon external address",
        source=AlertSource.SIEM,
        source_label="SIEM",
        timestamp=now,
        severity=AlertSeverity.HIGH,
        status=AlertStatus.OPEN,
        risk_score=70,
        hostname="srv-prod-app01",
        username="deployer",
        source_ip="198.51.100.44",
        destination_ip="10.0.1.5",
        indicators=["198.51.100.44"],
    )

    # Alert B: PowerShell / Bash execution on same host & user within 8 minutes
    alert_b = Alert(
        id="ALERT-TEST-02",
        title="Reverse shell command executed",
        description="Bash reverse shell spawned",
        source=AlertSource.EDR,
        source_label="EDR Endpoint Agent",
        timestamp=now + timedelta(minutes=8),
        severity=AlertSeverity.CRITICAL,
        status=AlertStatus.OPEN,
        risk_score=90,
        hostname="srv-prod-app01",
        username="deployer",
        source_ip="198.51.100.44",
        destination_ip="10.0.1.5",
        indicators=["198.51.100.44"],
    )

    score, reason, rule = CorrelationEngine.evaluate_pair(alert_a, alert_b)

    # Must have high correlation score (>= 0.75)
    assert score >= 0.75
    # Reason must explicitly explain why
    assert "Same host 'srv-prod-app01'" in reason
    assert "Same user account 'deployer'" in reason
    assert "Observed within 8 minutes" in reason


def test_weak_or_unrelated_alerts_not_correlated():
    """Verify that unrelated alerts with no shared assets and large time gap receive low score."""
    now = datetime.now(timezone.utc)

    alert_1 = Alert(
        id="ALERT-X",
        title="Benign print spooler start",
        description="Normal print spooler restart",
        source=AlertSource.EDR,
        source_label="EDR",
        timestamp=now,
        severity=AlertSeverity.LOW,
        status=AlertStatus.OPEN,
        risk_score=20,
        hostname="print-srv-01",
        username="service_print",
        source_ip="10.0.99.1",
        indicators=[],
    )

    alert_2 = Alert(
        id="ALERT-Y",
        title="Failed login attempt",
        description="User mistyped password on remote portal",
        source=AlertSource.SIEM,
        source_label="SIEM",
        timestamp=now - timedelta(days=7),
        severity=AlertSeverity.LOW,
        status=AlertStatus.OPEN,
        risk_score=25,
        hostname="vpn-portal-ext",
        username="john.doe",
        source_ip="203.0.113.8",
        indicators=[],
    )

    score, reason, rule = CorrelationEngine.evaluate_pair(alert_1, alert_2)
    assert score < 0.30
    assert reason == "Insufficient corroborating telemetry"


@pytest.mark.asyncio
async def test_trigger_correlation_api(async_client: AsyncClient):
    """Test POST /api/v1/threats/correlate endpoint."""
    res = await async_client.post("/api/v1/threats/correlate")
    assert res.status_code == 200
    data = res.json()
    assert "correlations_identified" in data
    assert "alerts_processed" in data
    assert data["alerts_processed"] > 0


@pytest.mark.asyncio
async def test_get_threats_api(async_client: AsyncClient):
    """Test GET /api/v1/threats returns full threat attributes."""
    res = await async_client.get("/api/v1/threats")
    assert res.status_code == 200
    threats = res.json()
    assert isinstance(threats, list)
    if len(threats) > 0:
        t = threats[0]
        assert "id" in t
        assert "title" in t
        assert "severity" in t
        assert "confidence" in t
        assert "riskScore" in t
        assert "alertCount" in t
        assert "affectedAssets" in t


@pytest.mark.asyncio
async def test_get_threat_details_and_timeline(async_client: AsyncClient):
    """Test GET /api/v1/threats/{id}/timeline and alerts."""
    res = await async_client.get("/api/v1/threats")
    threats = res.json()
    if threats:
        tid = threats[0]["id"]

        # 1. Detail
        detail_res = await async_client.get(f"/api/v1/threats/{tid}")
        assert detail_res.status_code == 200

        # 2. Timeline
        timeline_res = await async_client.get(f"/api/v1/threats/{tid}/timeline")
        assert timeline_res.status_code == 200
        assert isinstance(timeline_res.json(), list)

        # 3. Alerts
        alerts_res = await async_client.get(f"/api/v1/threats/{tid}/alerts")
        assert alerts_res.status_code == 200
        assert isinstance(alerts_res.json(), list)


@pytest.mark.asyncio
async def test_get_related_alerts_endpoint(async_client: AsyncClient):
    """Test GET /api/v1/alerts/{id}/related with explainable reason."""
    # First ingest two related alerts
    now = datetime.now(timezone.utc)
    a1_payload = {
        "id": "ALERT-CORR-01",
        "source": "siem",
        "title": "Brute force login detected",
        "hostname": "finance-vault",
        "username": "superadmin",
        "source_ip": "198.51.100.90",
        "timestamp": now.isoformat(),
        "severity": "high",
    }
    a2_payload = {
        "id": "ALERT-CORR-02",
        "source": "edr",
        "title": "Privilege escalation tool executed",
        "hostname": "finance-vault",
        "username": "superadmin",
        "source_ip": "198.51.100.90",
        "timestamp": (now + timedelta(minutes=5)).isoformat(),
        "severity": "critical",
    }
    await async_client.post("/api/v1/alerts", json=a1_payload)
    await async_client.post("/api/v1/alerts", json=a2_payload)

    # Trigger correlation
    await async_client.post("/api/v1/threats/correlate")

    # Check related endpoint
    rel_res = await async_client.get("/api/v1/alerts/ALERT-CORR-01/related")
    assert rel_res.status_code == 200
    related_list = rel_res.json()
    assert isinstance(related_list, list)
    if related_list:
        item = related_list[0]
        assert "correlationReason" in item
        assert "correlationScore" in item
        assert item["correlationScore"] >= 0.50
