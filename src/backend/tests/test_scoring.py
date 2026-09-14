import pytest
from httpx import AsyncClient
from datetime import datetime, timezone
from app.models.threat import Threat, ThreatSeverity, ThreatStatus
from app.models.alert import Alert, AlertSeverity, AlertSource
from app.services.threat_scoring import ThreatScoringEngine


def test_priority_bands_and_deterministic_scoring():
    """Verify priority bands are strictly bounded and reproducible without LLM."""
    assert ThreatScoringEngine.get_priority_band(10) == "LOW"
    assert ThreatScoringEngine.get_priority_band(24) == "LOW"
    assert ThreatScoringEngine.get_priority_band(25) == "MEDIUM"
    assert ThreatScoringEngine.get_priority_band(49) == "MEDIUM"
    assert ThreatScoringEngine.get_priority_band(50) == "HIGH"
    assert ThreatScoringEngine.get_priority_band(74) == "HIGH"
    assert ThreatScoringEngine.get_priority_band(75) == "CRITICAL"
    assert ThreatScoringEngine.get_priority_band(100) == "CRITICAL"


def test_threat_scoring_factors_breakdown():
    """Verify explainable individual scoring factors."""
    now = datetime.now(timezone.utc)
    threat = Threat(
        id="INC-CRITICAL-TEST",
        title="Kerberoasting on Domain Controller",
        summary="Active credential dumping against DC-01",
        severity=ThreatSeverity.CRITICAL,
        status=ThreatStatus.ACTIVE,
        alert_count=5,
        affected_assets=["Host: DC-01", "User: krbtgt"],
        mitre_techniques=["T1003", "T1078", "T1021.002"],
        opened_at=now,
        updated_at_custom=now,
    )

    alert = Alert(
        id="ALERT-MEM-01",
        title="LSASS memory access",
        description="Dumping LSASS",
        source=AlertSource.EDR,
        source_label="EDR",
        timestamp=now,
        severity=AlertSeverity.CRITICAL,
        hostname="DC-01",
        risk_score=90,
        metadata_info={
            "threat_intelligence": [
                {"indicator": "198.51.100.23", "reputation": "malicious"}
            ]
        },
    )

    assessment = ThreatScoringEngine.evaluate_threat_risk(threat, [alert], max_correlation_score=0.90)

    assert "risk_score" in assessment
    assert "priority" in assessment
    assert "factors" in assessment

    factors = assessment["factors"]
    assert factors["severity"] == 25
    assert factors["indicator_reputation"] == 20
    assert factors["asset_criticality"] == 15  # Because "DC-01" is domain controller
    assert factors["behavior"] >= 15  # T1003 is high-impact MITRE
    assert factors["correlation"] >= 15  # Alert count >= 4 and high correlation score

    assert assessment["risk_score"] >= 85
    assert assessment["priority"] == "CRITICAL"


@pytest.mark.asyncio
async def test_get_threat_risk_endpoint(async_client: AsyncClient):
    """Test GET /api/v1/threats/{id}/risk endpoint."""
    list_res = await async_client.get("/api/v1/threats")
    threats = list_res.json()
    assert len(threats) > 0
    tid = threats[0]["id"]

    risk_res = await async_client.get(f"/api/v1/threats/{tid}/risk")
    assert risk_res.status_code == 200
    risk_data = risk_res.json()

    assert "risk_score" in risk_data
    assert "priority" in risk_data
    assert "factors" in risk_data

    factors = risk_data["factors"]
    assert "severity" in factors
    assert "indicator_reputation" in factors
    assert "correlation" in factors
    assert "asset_criticality" in factors
    assert "behavior" in factors
    assert risk_data["priority"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@pytest.mark.asyncio
async def test_get_prioritized_threats_endpoint(async_client: AsyncClient):
    """Test GET /api/v1/threats/prioritized endpoint with risk descending sorting and priority filter."""
    res = await async_client.get("/api/v1/threats/prioritized")
    assert res.status_code == 200
    threats = res.json()
    assert isinstance(threats, list)
    assert len(threats) > 0

    # Verify descending sort order by risk_score
    if len(threats) >= 2:
        assert threats[0]["riskScore"] >= threats[1]["riskScore"]

    # Verify priority band filter
    prio_res = await async_client.get("/api/v1/threats/prioritized?priority=CRITICAL")
    assert prio_res.status_code == 200
    for t in prio_res.json():
        assert t["riskScore"] >= 75
        assert t["priority"] == "CRITICAL"
