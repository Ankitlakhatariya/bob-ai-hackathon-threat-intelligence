import pytest
import json
from unittest.mock import AsyncMock
from fastapi.testclient import TestClient
from fastapi.websockets import WebSocketDisconnect

from app.main import app
from app.services.websocket_manager import ConnectionManager
from app.core.security import create_access_token

client = TestClient(app)

@pytest.fixture
def mock_ws_token(mock_analyst_user):
    return create_access_token(
        data={"sub": str(mock_analyst_user.id), "role": mock_analyst_user.role.value, "email": mock_analyst_user.email}
    )

def test_websocket_authentication_success(mock_ws_token):
    """Test valid JWT allows WebSocket connection."""
    with client.websocket_connect(f"/api/v1/ws/threats?token={mock_ws_token}") as websocket:
        data = websocket.receive_json()
        assert data["event"] == "connection_established"
        assert data["data"]["status"] == "connected"

def test_websocket_missing_token():
    """Test missing token rejects connection."""
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/api/v1/ws/threats"):
            pass
    assert exc.value.code == 4003 or exc.value.code == 1008  # Typically policy violation

def test_websocket_invalid_token():
    """Test invalid token rejects connection."""
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/api/v1/ws/threats?token=invalid.token.here"):
            pass
    assert exc.value.code == 4003 or exc.value.code == 1008

def test_websocket_rbac_rejection(mock_viewer_user):
    """Test an unknown or unauthorized role is rejected."""
    token = create_access_token(
        data={"sub": str(mock_viewer_user.id), "role": "GUEST", "email": mock_viewer_user.email}
    )
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/api/v1/ws/threats?token={token}"):
            pass

@pytest.mark.asyncio
async def test_websocket_payload_sanitization(mock_threat):
    """Test that broadcast events send sanitized explicit schemas, not raw DB models or secrets."""
    manager = ConnectionManager()
    mock_ws = AsyncMock()
    
    await manager.connect(mock_ws, user_id="123", role="ANALYST")
    await manager.broadcast_threat_event("threat.updated", mock_threat)
    
    mock_ws.send_text.assert_called()
    call_args = mock_ws.send_text.call_args[0][0]
    payload = json.loads(call_args)
    
    assert payload["event"] == "threat.updated"
    assert "data" in payload
    threat_data = payload["data"]
    
    # Assert expected explicit fields exist
    assert threat_data["id"] == mock_threat.id
    assert threat_data["severity"] == mock_threat.severity.value
    
    # Assert no accidental SQLAlchemy internals or sensitive data
    assert "_sa_instance_state" not in threat_data
    assert "password" not in str(threat_data).lower()
    assert "secret" not in str(threat_data).lower()
