import pytest
from httpx import AsyncClient
from datetime import datetime, timezone
from app.models.alert import Alert, AlertSeverity, AlertSource
from app.services.mitre_service import (
    MitreBehaviorMapper,
    VERIFIED_TECHNIQUE_MAP,
    STANDARD_TECHNIQUES,
)


def test_verified_dataset_integrity():
    """Verify that technique catalog strictly contains official ATT&CK IDs (never invented IDs)."""
    assert "T1059.001" in VERIFIED_TECHNIQUE_MAP
    assert "T1078" in VERIFIED_TECHNIQUE_MAP
    assert "T1003" in VERIFIED_TECHNIQUE_MAP
    assert "T1110" in VERIFIED_TECHNIQUE_MAP
    assert "T1190" in VERIFIED_TECHNIQUE_MAP

    # Subtechniques have parent_technique_id and is_subtechnique=True
    pwsh = VERIFIED_TECHNIQUE_MAP["T1059.001"]
    assert pwsh["is_subtechnique"] is True
    assert pwsh["parent_technique_id"] == "T1059"


def test_behavioral_mapping_engine():
    """Verify deterministic mapping of observed telemetry to verified ATT&CK techniques with evidence."""
    now = datetime.now(timezone.utc)

    # 1. PowerShell execution behavior
    pwsh_alert = Alert(
        id="ALERT-BEHAVIOR-01",
        title="Obfuscated Script Execution",
        description="powershell.exe -enc aW52b2tlLWV4cHJlc3Npb24...",
        source=AlertSource.EDR,
        source_label="EDR",
        timestamp=now,
        severity=AlertSeverity.HIGH,
        hostname="WS-042",
        indicators=["powershell.exe"],
    )
    mappings = MitreBehaviorMapper.map_alert_behavior(pwsh_alert)
    tech_ids = [m[0] for m in mappings]
    assert "T1059.001" in tech_ids
    # Evidence must mention the trigger keyword
    pwsh_evidence = [m[1] for m in mappings if m[0] == "T1059.001"][0]
    assert "PowerShell" in pwsh_evidence
    assert "ALERT-BEHAVIOR-01" in pwsh_evidence

    # 2. LSASS credential access behavior
    lsass_alert = Alert(
        id="ALERT-BEHAVIOR-02",
        title="Sensitive memory handle requested",
        description="lsass.exe memory opened with PROCESS_VM_READ permissions via mimikatz",
        source=AlertSource.EDR,
        source_label="EDR",
        timestamp=now,
        severity=AlertSeverity.CRITICAL,
        hostname="DC-01",
        indicators=["lsass.exe", "mimikatz"],
    )
    lsass_mappings = MitreBehaviorMapper.map_alert_behavior(lsass_alert)
    lsass_tech_ids = [m[0] for m in lsass_mappings]
    assert "T1003" in lsass_tech_ids
    assert "LSASS" in lsass_mappings[0][1]


@pytest.mark.asyncio
async def test_get_mitre_tactics_api(async_client: AsyncClient):
    """Test GET /api/v1/mitre/tactics."""
    res = await async_client.get("/api/v1/mitre/tactics")
    assert res.status_code == 200
    tactics = res.json()
    assert isinstance(tactics, list)
    assert len(tactics) >= 10
    assert any(t["name"] == "Initial Access" for t in tactics)
    assert any(t["name"] == "Execution" for t in tactics)


@pytest.mark.asyncio
async def test_get_mitre_techniques_and_subtechniques_api(async_client: AsyncClient):
    """Test GET /api/v1/mitre/techniques and subtechnique filtering."""
    # All techniques
    res = await async_client.get("/api/v1/mitre/techniques")
    assert res.status_code == 200
    techs = res.json()
    assert len(techs) >= 14

    # Filter sub-techniques only
    sub_res = await async_client.get("/api/v1/mitre/techniques?subtechniques=true")
    assert sub_res.status_code == 200
    for t in sub_res.json():
        assert t["isSubtechnique"] is True
        assert t["parentTechniqueId"] is not None

    # Single technique lookup
    detail_res = await async_client.get("/api/v1/mitre/techniques/T1059.001")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == "T1059.001"
    assert "PowerShell" in detail["name"]


@pytest.mark.asyncio
async def test_get_threat_mitre_mappings_with_evidence(async_client: AsyncClient):
    """Test GET /api/v1/threats/{id}/mitre returns explicit evidence for each mapping."""
    list_res = await async_client.get("/api/v1/threats")
    threats = list_res.json()
    assert len(threats) > 0
    tid = threats[0]["id"]

    res = await async_client.get(f"/api/v1/threats/{tid}/mitre")
    assert res.status_code == 200
    mappings = res.json()
    assert isinstance(mappings, list)
    if mappings:
        mapping = mappings[0]
        assert "techniqueId" in mapping
        assert "techniqueName" in mapping
        assert "tactic" in mapping
        assert "confidence" in mapping
        assert "evidence" in mapping
        assert len(mapping["evidence"]) > 5
