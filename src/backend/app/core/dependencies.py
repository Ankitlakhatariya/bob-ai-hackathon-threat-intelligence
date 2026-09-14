from typing import Generator, AsyncGenerator, Optional, List, Dict, Any
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.security import jwt_validator
from app.database.session import AsyncSessionLocal
from app.core.logging import logger

security_scheme = HTTPBearer(auto_error=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_current_user_claims(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme)
) -> Optional[Dict[str, Any]]:
    """Extracts and verifies JWT claims from Supabase Bearer token if present."""
    if not credentials:
        return None
    token = credentials.credentials
    return jwt_validator.verify_token(token)


async def require_auth(
    claims: Optional[Dict[str, Any]] = Depends(get_current_user_claims)
) -> Dict[str, Any]:
    """Ensures an authenticated Supabase user is present."""
    if not claims:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "UNAUTHORIZED", "message": "Authentication required"}}
        )
    return claims


def require_roles(allowed_roles: List[str]):
    """Role-based access control dependency for endpoints."""
    async def role_checker(claims: Dict[str, Any] = Depends(require_auth)) -> Dict[str, Any]:
        app_metadata = claims.get("app_metadata", {})
        user_roles = app_metadata.get("roles", ["ANALYST"])
        if isinstance(user_roles, str):
            user_roles = [user_roles]

        # Check if user has at least one allowed role
        if not any(role in allowed_roles for role in user_roles) and "ADMIN" not in user_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": {"code": "FORBIDDEN", "message": "Insufficient permissions for this operation"}}
            )
        return claims
    return role_checker
