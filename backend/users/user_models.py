"""
User Models - Pydantic schemas for user operations
"""

from datetime import datetime as dt
from typing import Optional

from pydantic import BaseModel, EmailStr


# ================== Request Models ==================

class UserRegisterRequest(BaseModel):
    """User registration request body."""
    email: EmailStr
    password: str
    name: str
    phone: Optional[str] = None
    address: Optional[str] = None


# ================== Response Models ==================

class UserPublicResponse(BaseModel):
    """Public user information (minimal)."""
    user_id: str
    name: str
    photo_url: Optional[str] = None


class UserProfileResponse(BaseModel):
    """Full user profile response (for authenticated user)."""
    user_id: str
    email: str
    name: str
    phone: Optional[str] = None
    address: Optional[str] = None
    photo_url: Optional[str] = None
    is_active: bool
    is_verified: bool
    created_at: dt
    updated_at: dt


class UserResponse(BaseModel):
    """Standard user response wrapper."""
    status: int = 1
    message: str
    data: UserProfileResponse


# ================== Internal Models ==================

class UserCreate(BaseModel):
    """Internal model for creating a user."""
    user_id: str
    email: str
    name: str
    password_hash: str
    phone: Optional[str] = None
    address: Optional[str] = None
    photo_url: Optional[str] = None
    google_id: Optional[str] = None
    line_id: Optional[str] = None
    is_active: bool = True
    is_verified: bool = False
    created_at: dt
    updated_at: dt

