import pytest
from httpx import AsyncClient
from app.services.intelligence.manager import ThreatIntelManager
from app.models.indicator import IndicatorType, IndicatorReputation
from app.services.intelligence.provider import ExternalThreatIntelProvider


def test_indicator_type_detection():
    """Verify regex-based IOC syntax classification."""
    assert ThreatIntelManager.detect_indicator_type("198.51.100.23") == IndicatorType.IP
    assert ThreatIntelManager.detect_indicator_type("c2-beacon.darknet.org") == IndicatorType.DOMAIN
    assert ThreatIntelManager.detect_indicator_type("https://evil-site.com/payload.exe") == IndicatorType.URL
    assert ThreatIntelManager.detect_indicator_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == IndicatorType.HASH
    assert ThreatIntelManager.detect_indicator_type("d41d8cd98f00b204e9800998ecf8427e") == IndicatorType.HASH
    assert ThreatIntelManager.detect_indicator_type("phisher@malicious-domain.com") == IndicatorType.EMAIL


@pytest.mark.asyncio
async def test_unconfigured_external_provider_does_not_fabricate():
    """Verify that unconfigured providers return UNKNOWN rather than guessing or fabricating."""
    provider = ExternalThreatIntelProvider(api_key=None, base_url=None)
    assert provider.is_configured is False
    res = await provider.lookup("203.0.113.99", IndicatorType.IP)
    assert res is not None
    assert res.found is False
    assert res.reputation == IndicatorReputation.UNKNOWN
    assert res.confidence == 0


@pytest.mark.asyncio
async def test_indicator_crud_and_lookup(async_client: AsyncClient):
    """Test POST /api/v1/intelligence/indicators and GET lookup."""
    test_ip = "198.51.100.77"

    # Ingest a known malicious IOC
    create_payload = {
        "indicator": test_ip,
        "indicator_type": "ip",
        "reputation": "malicious",
        "confidence": 95,
        "source": "Mandiant Threat Intelligence",
        "threat_actor": "APT28 / Fancy Bear",
        "campaign": "Operation Ghostwriter",
        "tags": ["c2", "cobalt_strike"],
        "raw_intelligence": {"asn": "AS12345", "country": "RU"},
    }
    res = await async_client.post("/api/v1/intelligence/indicators", json=create_payload)
    assert res.status_code in [201, 400]  # 400 if already exists

    # Lookup the known IOC
    lookup_res = await async_client.get(f"/api/v1/intelligence/lookup/{test_ip}")
    assert lookup_res.status_code == 200
    lookup_data = lookup_res.json()
    assert lookup_data["found"] is True
    assert lookup_data["reputation"] == "malicious"
    assert lookup_data["confidence"] == 95
    assert lookup_data["threat_actor"] == "APT28 / Fancy Bear"
    assert lookup_data["campaign"] == "Operation Ghostwriter"


@pytest.mark.asyncio
async def test_lookup_unknown_indicator(async_client: AsyncClient):
    """Test lookup for unknown indicator returns unknown without fabrication."""
    unknown_ip = "192.0.2.188"
    lookup_res = await async_client.get(f"/api/v1/intelligence/lookup/{unknown_ip}")
    assert lookup_res.status_code == 200
    lookup_data = lookup_res.json()
    assert lookup_data["found"] is False
    assert lookup_data["reputation"] == "unknown"
    assert lookup_data["confidence"] == 0
    assert lookup_data["threat_actor"] is None


@pytest.mark.asyncio
async def test_alert_enrichment_on_ingestion(async_client: AsyncClient):
    """Test that an alert containing a malicious IOC is enriched automatically."""
    malicious_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    # Seed IOC
    await async_client.post(
        "/api/v1/intelligence/indicators",
        json={
            "indicator": malicious_hash,
            "reputation": "malicious",
            "confidence": 99,
            "threat_actor": "Lazarus Group",
            "campaign": "CryptoStealer",
            "tags": ["ransomware", "lazarus"],
        },
    )

    # Ingest alert containing the hash
    alert_payload = {
        "source": "edr",
        "title": "Suspect executable quarantined",
        "description": f"File hash {malicious_hash} detected on accounting endpoint",
        "file_hash": malicious_hash,
        "indicators": [malicious_hash],
        "severity": "medium",
    }
    alert_res = await async_client.post("/api/v1/alerts", json=alert_payload)
    assert alert_res.status_code == 201
    alert_data = alert_res.json()

    # Verify risk score was elevated and alert is high/critical
    assert alert_data["riskScore"] >= 65
