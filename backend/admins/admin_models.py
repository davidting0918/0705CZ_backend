"""
Admin Models - Pydantic schemas for admin operations
"""

from datetime import datetime as dt
from typing import Optional

from pydantic import BaseModel, EmailStr


# ================== Request Models ==================

class AdminRegisterRequest(BaseModel):
    """Admin registration request body."""
    email: EmailStr
    password: str
    name: str
    phone: Optional[str] = None
    photo_url: Optional[str] = None


class AdminUpdateRequest(BaseModel):
    """Admin update request body."""
    name: Optional[str] = None
    phone: Optional[str] = None
    photo_url: Optional[str] = None


class AdminGoogleLoginRequest(BaseModel):
    """Admin Google OAuth login request body."""
    token: str


# ================== Response Models ==================

class AdminPublicResponse(BaseModel):
    """Public admin information (minimal)."""
    admin_id: str
    name: str
    photo_url: Optional[str] = None


class AdminProfileResponse(BaseModel):
    """Full admin profile response (for authenticated admin)."""
    admin_id: str
    email: str
    name: str
    google_id: Optional[str] = None
    phone: Optional[str] = None
    photo_url: Optional[str] = None
    is_active: bool
    created_at: dt
    updated_at: dt


class AdminResponse(BaseModel):
    """Standard admin response wrapper."""
    status: int = 1
    message: str
    data: AdminProfileResponse


# ================== Internal Models ==================

class AdminCreate(BaseModel):
    """Internal model for creating an admin."""
    admin_id: str
    email: str
    name: str
    password_hash: Optional[str] = None
    google_id: Optional[str] = None
    phone: Optional[str] = None
    photo_url: Optional[str] = None
    is_active: bool = True
    created_at: dt
    updated_at: dt
