import json
from typing import List, Dict, Optional
from fastapi import WebSocket, WebSocketDisconnect
from app.core.logging import logger
from datetime import datetime, timezone
from app.schemas.ws import (
    AlertWSEvent, AlertWSData,
    ThreatWSEvent, ThreatWSData,
    InvestigationWSEvent, InvestigationWSData,
    IntelligenceWSEvent, IntelligenceWSData
)
from app.models.alert import Alert
from app.models.threat import Threat
from app.models.investigation import Investigation


class ConnectionManager:
    def __init__(self):
        # We track connections to avoid crashing and send to all connected clients.
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket, user_id: Optional[str] = None, role: Optional[str] = None):
        if hasattr(websocket, "accept"):
            await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected (user_id={user_id}, role={role}). Total active: {len(self.active_connections)}")
        welcome = {
            "event": "connection_established",
            "data": {"status": "connected"}
        }
        if hasattr(websocket, "send_json"):
            await websocket.send_json(welcome)
        elif hasattr(websocket, "send_text"):
            await websocket.send_text(json.dumps(welcome))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket disconnected. Total active: {len(self.active_connections)}")

    async def _broadcast_json(self, payload: dict):
        # Safe broadcasting that handles disconnections mid-loop
        if "event" not in payload and "event_type" in payload:
            payload["event"] = payload["event_type"]
        text_payload = json.dumps(payload)
        dead_connections = []
        for connection in self.active_connections:
            try:
                if hasattr(connection, "send_text"):
                    await connection.send_text(text_payload)
                elif hasattr(connection, "send_json"):
                    await connection.send_json(payload)
            except WebSocketDisconnect:
                dead_connections.append(connection)
            except Exception as e:
                logger.error(f"Error broadcasting to WebSocket: {e}")
                dead_connections.append(connection)
                
        for dead in dead_connections:
            self.disconnect(dead)
            
        logger.debug(f"Broadcasted to {len(self.active_connections)} clients")

    # Domain-specific broadcast methods that enforce schema validation
    async def broadcast_alert_event(self, event_type: str, alert: Alert):
        now = datetime.now(timezone.utc)
        data = AlertWSData(
            alert_id=alert.id,
            severity=alert.severity,
            source=alert.source.value if hasattr(alert.source, 'value') else str(alert.source),
            event_type=alert.event_type,
            timestamp=alert.timestamp or now
        )
        event = AlertWSEvent(event_type=event_type, event=event_type, timestamp=now, data=data)
        await self._broadcast_json(event.model_dump(mode='json'))

    async def broadcast_threat_event(self, event_type: str, threat: Threat):
        now = datetime.now(timezone.utc)
        data = ThreatWSData(
            id=threat.id,
            threat_id=threat.threat_id or threat.id,
            title=threat.title,
            severity=threat.severity,
            risk_score=threat.risk_score,
            confidence=threat.confidence,
            status=threat.status,
            alert_count=threat.alert_count
        )
        event = ThreatWSEvent(event_type=event_type, event=event_type, timestamp=now, data=data)
        await self._broadcast_json(event.model_dump(mode='json'))

    async def broadcast_investigation_event(self, event_type: str, investigation: Investigation):
        now = datetime.now(timezone.utc)
        data = InvestigationWSData(
            investigation_id=str(investigation.id),
            threat_id=investigation.threat_id,
            status=investigation.status.value if hasattr(investigation.status, 'value') else str(investigation.status),
            priority=investigation.priority.value if hasattr(investigation.priority, 'value') else str(investigation.priority)
        )
        event = InvestigationWSEvent(event_type=event_type, timestamp=now, data=data)
        await self._broadcast_json(event.model_dump(mode='json'))

    async def broadcast_intelligence_event(self, event_type: str, indicator: str, threat_actor: str, matched_alerts: List[str]):
        now = datetime.now(timezone.utc)
        data = IntelligenceWSData(
            indicator_value=indicator,
            threat_actor=threat_actor,
            matched_alert_ids=matched_alerts
        )
        event = IntelligenceWSEvent(event_type=event_type, timestamp=now, data=data)
        await self._broadcast_json(event.model_dump(mode='json'))


# Singleton instance
ws_manager = ConnectionManager()
