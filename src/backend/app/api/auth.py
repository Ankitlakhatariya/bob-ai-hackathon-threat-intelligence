from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.dependencies import get_db, get_current_user_claims
from app.models.user import User, UserRole
from app.schemas.auth import UserProfile, AuthResponse
from app.core.logging import logger

router = APIRouter()


@router.get("/me", response_model=AuthResponse)
async def get_current_user_profile(
    claims: Optional[Dict[str, Any]] = Depends(get_current_user_claims),
    db: AsyncSession = Depends(get_db),
):
    """Identifies the Supabase user from JWT, synchronizes the database profile, and returns role/profile info."""
    if not claims:
        # Graceful demo fallback if token is not provided
        return AuthResponse(
            user=UserProfile(
                supabase_id="demo-analyst-id",
                email="demo-analyst@threatlens.soc",
                full_name="Demo SOC Analyst",
                role=UserRole.ANALYST,
                is_active=True,
            ),
            role="ANALYST",
            token_type="Bearer"
        )

    supabase_id = claims.get("sub") or claims.get("id")
    email = claims.get("email") or f"{supabase_id}@auth.supabase.co"

    if not supabase_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "INVALID_CLAIMS", "message": "JWT does not contain user subject"}}
        )

    stmt = select(User).where(User.supabase_id == supabase_id)
    res = await db.execute(stmt)
    user = res.scalars().first()

    app_metadata = claims.get("app_metadata", {})
    user_metadata = claims.get("user_metadata", {})
    claim_roles = app_metadata.get("roles", ["ANALYST"])
    role_str = claim_roles[0] if isinstance(claim_roles, list) and claim_roles else "ANALYST"
    role_enum = getattr(UserRole, role_str.upper(), UserRole.ANALYST)

    if not user:
        user = User(
            supabase_id=supabase_id,
            email=email,
            full_name=user_metadata.get("full_name") or user_metadata.get("name") or email.split("@")[0],
            role=role_enum,
            is_active=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

    return AuthResponse(
        user=UserProfile.model_validate(user),
        role=user.role.value,
        token_type="Bearer"
    )
