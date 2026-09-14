import pytest
from httpx import AsyncClient
from datetime import datetime, timezone, timedelta
from app.services.ingestion import AlertIngestionEngine
from app.models.alert import AlertSource, AlertSeverity


def test_edr_normalization():
    """Verify EDR vendor payload normalization and indicator extraction."""
    raw_edr = {
        "event_id": "EDR-9988",
        "vendor": "CrowdStrike Falcon",
        "computer_name": "FINANCE-WS01",
        "user": "alice.smith",
        "process_name": "mimikatz.exe",
        "cmdline": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "severity": "critical",
        "time": "2026-09-14T10:30:00Z",
        "techniques": ["T1003"],
    }
    event = AlertIngestionEngine.normalize_event(raw_edr)
    assert event.source == AlertSource.EDR
    assert event.hostname == "FINANCE-WS01"
    assert event.username == "alice.smith"
    assert event.process_name == "mimikatz.exe"
    assert event.severity == AlertSeverity.CRITICAL
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in event.indicators
    assert event.raw_data == raw_edr


def test_siem_normalization():
    """Verify SIEM payload normalization."""
    raw_siem = {
        "offense_id": "SIEM-5544",
        "log_source": "IBM QRadar",
        "rule_name": "Excessive Failed Logins Followed by Success",
        "sourceIPAddress": "198.51.100.50",
        "destinationIPAddress": "10.0.1.10",
        "sourceUserName": "admin_svc",
        "magnitude": 8,  # Scale 1-10 -> Critical
        "start_time": "2026-09-14T11:00:00Z",
    }
    event = AlertIngestionEngine.normalize_event(raw_siem)
    assert event.source == AlertSource.SIEM
    assert event.source_ip == "198.51.100.50"
    assert event.destination_ip == "10.0.1.10"
    assert event.username == "admin_svc"
    assert "198.51.100.50" in event.indicators


def test_firewall_normalization():
    """Verify Firewall traffic event normalization."""
    raw_fw = {
        "id": "FW-1029",
        "vendor": "Palo Alto Networks",
        "src_ip": "10.0.2.15",
        "dst_ip": "192.0.2.200",
        "dport": 443,
        "proto": "TCP",
        "action": "blocked",
        "policy_name": "Deny_Untrusted_Egress",
    }
    event = AlertIngestionEngine.normalize_event(raw_fw)
    assert event.source == AlertSource.NETWORK_SENSOR
    assert event.source_ip == "10.0.2.15"
    assert event.destination_ip == "192.0.2.200"
    assert event.destination_port == 443


def test_network_sensor_normalization():
    """Verify Zeek/Suricata network sensor normalization."""
    raw_zeek = {
        "uid": "NET-7711",
        "source": "Zeek NIDS",
        "id.orig_h": "10.0.3.5",
        "id.resp_h": "203.0.113.7",
        "id.resp_p": 8080,
        "alert": {"signature": "Suspicious HTTP Header Value", "severity": "medium"},
    }
    event = AlertIngestionEngine.normalize_event(raw_zeek)
    assert event.source == AlertSource.NETWORK_SENSOR
    assert event.source_ip == "10.0.3.5"
    assert event.destination_ip == "203.0.113.7"
    assert event.destination_port == 8080


def test_threat_intel_feed_normalization():
    """Verify Threat Intelligence Feed normalization."""
    raw_intel = {
        "id": "INTEL-4433",
        "source": "threat-feed",
        "indicator_value": "malicious-domain.com",
        "threat_actor": "APT29",
        "severity": "high",
    }
    event = AlertIngestionEngine.normalize_event(raw_intel)
    assert event.source == AlertSource.THREAT_FEED
    assert "malicious-domain.com" in event.indicators


@pytest.mark.asyncio
async def test_alert_ingestion_api(async_client: AsyncClient):
    """Test POST /api/v1/alerts ingestion endpoint with raw EDR payload."""
    payload = {
        "source": "edr",
        "hostname": "PROD-DB-01",
        "username": "dbadmin",
        "process_name": "cmd.exe",
        "command_line": "cmd.exe /c whoami",
        "severity": "high",
        "description": "Suspicious shell invocation on database server",
        "custom_vendor_tag": "Falcon-Detection-99",
    }
    res = await async_client.post("/api/v1/alerts", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert "id" in data
    assert data["source"] == "edr"
    assert data["hostname"] == "PROD-DB-01"
    assert data["username"] == "dbadmin"
    assert data["riskScore"] >= 50
    alert_id = data["id"]

    # Retrieve and verify rawData is 100% preserved
    get_res = await async_client.get(f"/api/v1/alerts/{alert_id}")
    assert get_res.status_code == 200
    alert_data = get_res.json()
    assert alert_data["rawData"]["custom_vendor_tag"] == "Falcon-Detection-99"

    # Test deletion
    del_res = await async_client.delete(f"/api/v1/alerts/{alert_id}")
    assert del_res.status_code == 204


@pytest.mark.asyncio
async def test_bulk_alert_ingestion_api(async_client: AsyncClient):
    """Test POST /api/v1/alerts/bulk with mixed vendor events."""
    bulk_payload = [
        {
            "source": "siem",
            "source_ip": "198.51.100.99",
            "destination_ip": "10.0.0.1",
            "severity": "critical",
            "title": "Brute force attack detected by SIEM",
            "description": "Multiple failed auths followed by success",
        },
        {
            "source": "edr",
            "hostname": "WS-099",
            "username": "victim_user",
            "severity": "high",
            "title": "Powershell download cradle detected",
            "description": "powershell.exe -enc aW52b2tl...",
        },
    ]
    res = await async_client.post("/api/v1/alerts/bulk", json=bulk_payload)
    assert res.status_code == 201
    data = res.json()
    assert data["ingested_count"] == 2
    assert len(data["alert_ids"]) == 2
    assert data["correlation_triggered"] is True


@pytest.mark.asyncio
async def test_alert_filtering_and_sorting(async_client: AsyncClient):
    """Test advanced query parameters: severity, ip, hostname, username, sorting."""
    # Filter by severity
    res_sev = await async_client.get("/api/v1/alerts?severity=critical")
    assert res_sev.status_code == 200
    for a in res_sev.json():
        assert a["severity"] == "critical"

    # Filter by source
    res_src = await async_client.get("/api/v1/alerts?source=siem")
    assert res_src.status_code == 200
    for a in res_src.json():
        assert a["source"] == "siem"

    # Sort by risk_score descending
    res_sort = await async_client.get("/api/v1/alerts?sort_by=risk_score&sort_order=desc&limit=5")
    assert res_sort.status_code == 200
    items = res_sort.json()
    if len(items) >= 2:
        assert items[0]["riskScore"] >= items[1]["riskScore"]
