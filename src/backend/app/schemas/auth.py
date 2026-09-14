from typing import Optional
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from app.models.user import UserRole


class UserProfile(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[UUID] = None
    supabase_id: str
    email: str
    full_name: Optional[str] = None
    role: UserRole
    is_active: bool = True
    created_at: Optional[datetime] = None


class AuthResponse(BaseModel):
    user: UserProfile
    role: str
    token_type: str = "Bearer"
