from typing import Optional, List
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from app.core.permissions import UserRole


class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, description="Minimum 8 characters")
    full_name: Optional[str] = None
    role: UserRole = UserRole.ANALYST


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class UserProfile(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[UUID] = None
    supabase_id: Optional[str] = None
    email: str
    full_name: Optional[str] = None
    role: UserRole
    permissions: List[str] = []
    is_active: bool = True
    created_at: Optional[datetime] = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = 86400  # 24 hours in seconds
    user: UserProfile


class AuthResponse(BaseModel):
    user: UserProfile
    role: str
    token_type: str = "Bearer"
