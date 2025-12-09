"""
Auth Services - Business logic for authentication

Handles three authentication methods:
1. Session (HTTP-only cookie) - for user website login
2. Access Token (JWT) - for staff dashboard
3. API Key - for frontend public endpoints
"""

import os
from datetime import datetime as dt
from datetime import timezone as tz
from typing import Optional

import httpx
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from backend.core.db_manager import get_db
from backend.core.security import (
    SESSION_COOKIE_NAME,
    create_access_token,
    decode_access_token,
    generate_session_token,
    generate_user_id,
    get_session_expiry,
    get_token_expiry,
    hash_password,
    hash_token,
    verify_password,
)
from backend.auth.auth_models import (
    AccessTokenData,
    GoogleUserInfo,
    LineUserInfo,
    SessionData,
)

load_dotenv("backend/.env")

# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class AuthService:
    """Authentication service handling all auth methods."""

    def __init__(self):
        self.google_client_id = os.getenv("GOOGLE_CLIENT_ID")
        self.google_client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
        self.line_client_id = os.getenv("LINE_CLIENT_ID")
        self.line_client_secret = os.getenv("LINE_CLIENT_SECRET")
        self.line_redirect_uri = os.getenv("LINE_REDIRECT_URI", "http://localhost:8000/auth/line/callback")

    @property
    def db(self):
        """Get database client from global manager."""
        return get_db()

    # ================== Email/Password Authentication ==================

    async def authenticate_by_email(self, email: str, password: str) -> Optional[dict]:
        """
        Authenticate user by email and password.
        
        Returns user dict if valid, None otherwise.
        """
        query = "SELECT * FROM users WHERE email = $1 AND is_active = TRUE"
        user = await self.db.read_one(query, email)

        if not user:
            return None

        if not verify_password(password, user["password_hash"]):
            return None

        return user

    async def authenticate_by_name(self, name: str, password: str) -> Optional[dict]:
        """
        Authenticate user by name and password (for staff access token).
        
        Returns user dict if valid, None otherwise.
        """
        query = "SELECT * FROM users WHERE name = $1 AND is_active = TRUE"
        user = await self.db.read_one(query, name)

        if not user:
            return None

        if not verify_password(password, user["password_hash"]):
            return None

        return user

    # ================== Google OAuth ==================

    async def verify_google_token(self, token: str) -> Optional[GoogleUserInfo]:
        """Verify Google OAuth token and get user info."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"https://www.googleapis.com/oauth2/v3/userinfo",
                    headers={"Authorization": f"Bearer {token}"}
                )
                if response.status_code != 200:
                    return None
                
                data = response.json()
                return GoogleUserInfo(
                    id=data["sub"],
                    email=data["email"],
                    name=data.get("name", data["email"]),
                    picture=data.get("picture"),
                )
        except Exception:
            return None

    async def authenticate_google_user(self, token: str) -> Optional[dict]:
        """
        Authenticate via Google OAuth.
        Creates user if not exists, updates google_id if needed.
        """
        google_info = await self.verify_google_token(token)
        if not google_info:
            return None

        # Try to find user by email
        query = "SELECT * FROM users WHERE email = $1"
        user = await self.db.read_one(query, google_info.email)

        if user:
            # Update google_id if not set
            if not user.get("google_id"):
                update_query = """
                    UPDATE users 
                    SET google_id = $1, photo_url = $2, updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = $3
                """
                await self.db.execute(update_query, google_info.id, google_info.picture, user["user_id"])
                user["google_id"] = google_info.id
                user["photo_url"] = google_info.picture
            return user
        else:
            # Create new user
            new_user = await self._create_oauth_user(
                email=google_info.email,
                name=google_info.name,
                photo_url=google_info.picture,
                google_id=google_info.id,
            )
            return new_user

    # ================== LINE OAuth ==================

    def get_line_authorization_url(self, state: str, redirect_uri: Optional[str] = None) -> str:
        """Generate LINE OAuth authorization URL."""
        uri = redirect_uri or self.line_redirect_uri
        params = {
            "response_type": "code",
            "client_id": self.line_client_id,
            "redirect_uri": uri,
            "state": state,
            "scope": "profile openid email",
        }
        query = "&".join(f"{k}={v}" for k, v in params.items())
        return f"https://access.line.me/oauth2/v2.1/authorize?{query}"

    async def exchange_line_code(self, code: str, redirect_uri: Optional[str] = None) -> Optional[str]:
        """Exchange LINE authorization code for access token."""
        uri = redirect_uri or self.line_redirect_uri
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://api.line.me/oauth2/v2.1/token",
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": uri,
                        "client_id": self.line_client_id,
                        "client_secret": self.line_client_secret,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                if response.status_code != 200:
                    return None
                
                data = response.json()
                return data.get("access_token")
        except Exception:
            return None

    async def get_line_user_info(self, access_token: str) -> Optional[LineUserInfo]:
        """Get LINE user profile info."""
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://api.line.me/v2/profile",
                    headers={"Authorization": f"Bearer {access_token}"}
                )
                if response.status_code != 200:
                    return None
                
                data = response.json()
                return LineUserInfo(
                    user_id=data["userId"],
                    display_name=data["displayName"],
                    picture_url=data.get("pictureUrl"),
                    email=data.get("email"),
                )
        except Exception:
            return None

    async def authenticate_line_user(self, code: str, redirect_uri: Optional[str] = None) -> Optional[dict]:
        """
        Authenticate via LINE OAuth.
        Creates user if not exists.
        """
        access_token = await self.exchange_line_code(code, redirect_uri)
        if not access_token:
            return None

        line_info = await self.get_line_user_info(access_token)
        if not line_info:
            return None

        # Try to find user by line_id
        query = "SELECT * FROM users WHERE line_id = $1"
        user = await self.db.read_one(query, line_info.user_id)

        if user:
            return user

        # Try to find by email if available
        if line_info.email:
            query = "SELECT * FROM users WHERE email = $1"
            user = await self.db.read_one(query, line_info.email)
            if user:
                # Update line_id
                update_query = """
                    UPDATE users 
                    SET line_id = $1, photo_url = COALESCE(photo_url, $2), updated_at = CURRENT_TIMESTAMP
                    WHERE user_id = $3
                """
                await self.db.execute(update_query, line_info.user_id, line_info.picture_url, user["user_id"])
                user["line_id"] = line_info.user_id
                return user

        # Create new user (use LINE user_id as placeholder email if no email)
        email = line_info.email or f"{line_info.user_id}@line.placeholder"
        new_user = await self._create_oauth_user(
            email=email,
            name=line_info.display_name,
            photo_url=line_info.picture_url,
            line_id=line_info.user_id,
        )
        return new_user

    # ================== User Creation ==================

    async def _create_oauth_user(
        self,
        email: str,
        name: str,
        photo_url: Optional[str] = None,
        google_id: Optional[str] = None,
        line_id: Optional[str] = None,
    ) -> dict:
        """Create a new user from OAuth login."""
        user_id = generate_user_id()
        
        # Ensure unique user_id
        while await self.db.read_one("SELECT 1 FROM users WHERE user_id = $1", user_id):
            user_id = generate_user_id()

        # Generate a random password hash for OAuth users
        password_hash = hash_password(f"oauth_{user_id}_{dt.now(tz.utc).timestamp()}")

        user_data = {
            "user_id": user_id,
            "email": email,
            "name": name,
            "password_hash": password_hash,
            "photo_url": photo_url,
            "google_id": google_id,
            "line_id": line_id,
            "is_active": True,
            "is_verified": True,
            "created_at": dt.now(tz.utc),
            "updated_at": dt.now(tz.utc),
        }

        await self.db.insert_one("users", user_data)
        return user_data

    # ================== Session Management ==================

    async def create_session(
        self,
        user_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> tuple[str, SessionData]:
        """
        Create a new session for user.
        
        Returns (raw_token, session_data) tuple.
        """
        token = generate_session_token()
        token_hash = hash_token(token)
        expires_at = get_session_expiry()

        session_data = SessionData(
            user_id=user_id,
            token_hash=token_hash,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at,
        )

        await self.db.insert_one("sessions", {
            "user_id": session_data.user_id,
            "token_hash": session_data.token_hash,
            "ip_address": session_data.ip_address,
            "user_agent": session_data.user_agent,
            "expires_at": session_data.expires_at,
        })

        return token, session_data

    async def validate_session(self, token: str) -> Optional[dict]:
        """
        Validate session token and return user if valid.
        """
        token_hash = hash_token(token)
        
        query = """
            SELECT u.* FROM sessions s
            JOIN users u ON s.user_id = u.user_id
            WHERE s.token_hash = $1 
            AND s.expires_at > CURRENT_TIMESTAMP
            AND u.is_active = TRUE
        """
        user = await self.db.read_one(query, token_hash)
        return user

    async def delete_session(self, token: str) -> bool:
        """Delete a session (logout)."""
        token_hash = hash_token(token)
        result = await self.db.execute(
            "DELETE FROM sessions WHERE token_hash = $1",
            token_hash
        )
        return "DELETE" in result

    # ================== Access Token Management ==================

    async def create_access_token_record(self, user_id: str) -> tuple[str, AccessTokenData]:
        """
        Create a JWT access token and store hash in database.
        
        Returns (jwt_token, token_data) tuple.
        """
        jwt_token = create_access_token(user_id)
        token_hash = hash_token(jwt_token)
        expires_at = get_token_expiry()

        token_data = AccessTokenData(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
        )

        await self.db.insert_one("access_tokens", {
            "user_id": token_data.user_id,
            "token_hash": token_data.token_hash,
            "expires_at": token_data.expires_at,
        })

        return jwt_token, token_data

    async def validate_access_token(self, token: str) -> Optional[dict]:
        """
        Validate JWT access token and return user if valid.
        """
        # First decode JWT
        payload = decode_access_token(token)
        if not payload:
            return None

        user_id = payload.get("sub")
        if not user_id:
            return None

        # Verify token exists in database and not expired
        token_hash = hash_token(token)
        query = """
            SELECT u.* FROM access_tokens t
            JOIN users u ON t.user_id = u.user_id
            WHERE t.token_hash = $1 
            AND t.expires_at > CURRENT_TIMESTAMP
            AND u.is_active = TRUE
        """
        user = await self.db.read_one(query, token_hash)
        return user

    # ================== API Key Validation ==================

    async def validate_api_key(self, api_key: str, api_secret: str) -> Optional[dict]:
        """
        Validate API key and secret.
        
        Returns API key info if valid.
        """
        query = """
            SELECT * FROM api_keys 
            WHERE api_key = $1 AND api_secret = $2 AND is_active = TRUE
        """
        key_info = await self.db.read_one(query, api_key, api_secret)
        return key_info


# Global auth service instance
auth_service = AuthService()


# ================== FastAPI Dependencies ==================

async def get_current_user_session(request: Request) -> dict:
    """
    Dependency: Get current user from session cookie.
    Used for user website authentication.
    """
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    user = await auth_service.validate_session(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    return user


async def get_current_user_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> dict:
    """
    Dependency: Get current user from JWT access token.
    Used for staff dashboard authentication.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = await auth_service.validate_access_token(credentials.credentials)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


async def verify_api_key(api_key_value: Optional[str] = Depends(api_key_header)) -> dict:
    """
    Dependency: Verify API key from header.
    Used for frontend public endpoint authentication.
    
    Expects header format: X-API-Key: key:secret
    """
    if not api_key_value:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
        )

    if ":" not in api_key_value:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format. Expected: key:secret",
        )

    key, secret = api_key_value.split(":", 1)
    key_info = await auth_service.validate_api_key(key, secret)

    if not key_info:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key or secret",
        )

    return key_info
