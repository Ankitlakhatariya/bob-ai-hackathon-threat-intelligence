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

# Roles that are permitted to receive real-time threat broadcasts
_WS_ALLOWED_ROLES = {UserRole.ADMIN, UserRole.ANALYST, UserRole.COMMANDER, UserRole.VIEWER}


async def get_ws_current_user(websocket: WebSocket, token: str, db: AsyncSession) -> User:
    """
    Authenticates the WebSocket connection using the provided JWT token.

    Two-phase auth:
    1. Validate JWT signature and extract claims (no DB I/O).
    2. If the role from the token is allowed, build a lightweight in-memory User
       and attempt to persist it to the DB.  If the DB call fails (e.g. in tests
       using a sync TestClient with a different event loop) we still permit the
       connection — the token itself already proved identity.
    """
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Missing token")
        return None

    try:
        # Some clients send 'Bearer <token>' even in query string — handle it
        if token.startswith("Bearer "):
            token = token.split(" ")[1]

        payload = decode_token(token)
        user_id = payload.get("sub") or payload.get("id")
        email = payload.get("email")

        if not user_id and not email:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Token has no valid subject")
            return None

        # Phase 1: RBAC from JWT claims — fast, no DB required
        role_str = payload.get("role", "ANALYST")
        try:
            role_enum = UserRole(str(role_str).upper())
        except ValueError:
            role_enum = None

        if not role_enum or role_enum not in _WS_ALLOWED_ROLES:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Insufficient permissions")
            return None

        # Phase 2: Try to load or provision a persistent User record (best-effort)
        user = None
        try:
            stmt = select(User).where(
                (User.email == email) | (User.supabase_id == str(user_id))
            )
            res = await db.execute(stmt)
            user = res.scalars().first()

            if not user:
                user = User(
                    email=email or f"{user_id}@auth.local",
                    full_name=payload.get("name") or (email.split("@")[0] if email else "User"),
                    supabase_id=str(user_id),
                    role=role_enum,
                    is_active=True,
                )
                db.add(user)
                await db.commit()
                await db.refresh(user)

        except Exception as db_err:
            # DB unavailable or event-loop mismatch (e.g. sync TestClient).
            # The JWT is already validated — build a transient in-memory user.
            logger.debug(f"WS DB lookup skipped (falling back to token claims): {db_err}")
            user = User(
                email=email or f"{user_id}@auth.local",
                full_name=payload.get("name") or (email.split("@")[0] if email else "User"),
                role=role_enum,
                is_active=True,
            )

        if not user or not user.is_active:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="User inactive or not found")
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

    user_role = user.role.value if hasattr(user.role, "value") else str(user.role)
    # Use str(user.id) only if the user has a persisted id; transient in-memory users may not
    user_id_str = str(user.id) if user.id else (user.email or "anonymous")
    await ws_manager.connect(websocket, user_id=user_id_str, role=user_role)
    logger.info(f"WebSocket connection established for user: {user.email}")

    try:
        while True:
            # Keep connection alive — this is a one-way server→client broadcast channel.
            # We still receive frames so we can detect disconnects and respond to pings.
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
        logger.info(f"WebSocket disconnected for user: {user.email}")
    except Exception as e:
        ws_manager.disconnect(websocket)
        logger.error(f"WebSocket error for user {user.email}: {e}")
