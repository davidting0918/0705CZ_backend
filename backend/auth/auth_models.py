"""
Auth Models - Pydantic schemas for authentication
"""

import os
from datetime import datetime as dt
from typing import Optional

from dotenv import load_dotenv
from pydantic import BaseModel, EmailStr

load_dotenv("backend/.env")


# ================== Request Models ==================

class EmailLoginRequest(BaseModel):
    """Email login request body."""
    email: EmailStr
    password: str


class GoogleLoginRequest(BaseModel):
    """Google OAuth login request body."""
    token: str


class LineLoginRequest(BaseModel):
    """LINE login initiation request."""
    redirect_uri: Optional[str] = None


# ================== Response Models ==================

class UserResponse(BaseModel):
    """User data in auth responses."""
    user_id: str
    email: str
    name: str
    photo_url: Optional[str] = None


class SessionLoginResponse(BaseModel):
    """Response for session-based login (user website)."""
    status: int = 1
    message: str
    data: UserResponse


class AccessTokenResponse(BaseModel):
    """Response for access token request (staff dashboard)."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    message: str


class LineLoginResponse(BaseModel):
    """Response for LINE login initiation."""
    authorization_url: str


# ================== Internal Models ==================

class GoogleUserInfo(BaseModel):
    """User info from Google OAuth."""
    id: str
    email: str
    name: str
    picture: Optional[str] = None


class LineUserInfo(BaseModel):
    """User info from LINE OAuth."""
    user_id: str
    display_name: str
    picture_url: Optional[str] = None
    email: Optional[str] = None


class SessionData(BaseModel):
    """Session data stored in database."""
    id: Optional[str] = None
    user_id: str
    token_hash: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    expires_at: dt
    created_at: Optional[dt] = None
    updated_at: Optional[dt] = None


class AccessTokenData(BaseModel):
    """Access token data stored in database."""
    id: Optional[int] = None
    user_id: str
    token_hash: str
    expires_at: dt
    created_at: Optional[dt] = None
    updated_at: Optional[dt] = None
