from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.dependencies import get_db
from app.core.security import decode_token
from app.models.user import User
from app.core.permissions import UserRole
from app.services.websocket_manager import ws_manager
from app.core.logging import logger

router = APIRouter()

async def get_ws_current_user(websocket: WebSocket, token: str, db: AsyncSession) -> User:
    """Authenticates the WebSocket connection using the provided JWT token."""
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Missing token")
        return None

    try:
        # Some clients send 'Bearer <token>' even in query string, handle it
        if token.startswith("Bearer "):
            token = token.split(" ")[1]
            
        payload = decode_token(token)
        user_id = payload.get("sub") or payload.get("id")
        email = payload.get("email")

        if not user_id and not email:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Token has no valid subject")
            return None

        stmt = select(User).where((User.email == email) | (User.supabase_id == str(user_id)))
        res = await db.execute(stmt)
        user = res.scalars().first()

        if not user or not user.is_active:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="User inactive or not found")
            return None

        # RBAC Check
        allowed_roles = [UserRole.ADMIN, UserRole.ANALYST, UserRole.COMMANDER, UserRole.VIEWER]
        if user.role not in allowed_roles:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Insufficient permissions")
            return None

        return user
    except Exception as e:
        logger.warning(f"WebSocket authentication failed: {e}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid token")
        return None


@router.websocket("/threats")
async def websocket_threats(
    websocket: WebSocket,
    token: str = Query(None),
    db: AsyncSession = Depends(get_db)
):
    """
    WebSocket endpoint for real-time threat updates.
    Requires a valid JWT token passed as a query parameter (?token=).
    """
    user = await get_ws_current_user(websocket, token, db)
    if not user:
        return

    await ws_manager.connect(websocket)
    logger.info(f"WebSocket connection established for user: {user.email}")

    try:
        while True:
            # We keep the connection alive. We don't expect client messages for this one-way broadcast.
            # But we wait to handle disconnects gracefully.
            data = await websocket.receive_text()
            # Respond to pings if needed
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
        logger.info(f"WebSocket disconnected for user: {user.email}")
    except Exception as e:
        ws_manager.disconnect(websocket)
        logger.error(f"WebSocket error for user {user.email}: {e}")
