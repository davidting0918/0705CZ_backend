"""
Auth Services - Business logic for authentication

Handles two authentication methods:
1. Session (HTTP-only cookie) - for user website login
2. Access Token (JWT) - for staff dashboard
"""

import os
from datetime import datetime as dt
from datetime import timezone as tz
from typing import Optional

import httpx
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.core.db_manager import get_db
from backend.core.security import (
    SESSION_COOKIE_NAME,
    create_access_token,
    decode_access_token,
    generate_session_token,
    generate_user_id,
    get_session_expiry,
    get_token_expiry,
    hash_password_user,
    hash_token,
    verify_password,
)
from backend.auth.auth_models import (
    AccessTokenData,
    GoogleUserInfo,
    LineUserInfo,
    SessionData,
)
from backend.admins.admin_whitelist_service import admin_whitelist_service
from backend.admins.admin_services import admin_service

load_dotenv("backend/.env")

# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)


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

    async def _authenticate_user(
        self,
        field: str,
        value: str,
        password: str,
    ) -> Optional[dict]:
        """
        Generic user authentication by field (email or name).
        
        Args:
            field: Field name to query (email or name)
            value: Field value to match
            password: Password to verify
            
        Returns:
            User dict if valid, None otherwise
        """
        query = f"SELECT * FROM users WHERE {field} = $1 AND is_active = TRUE"
        user = await self.db.read_one(query, value)

        if not user:
            return None

        if not verify_password(password, user["password_hash"]):
            return None

        return user

    async def authenticate_by_email(self, email: str, password: str) -> Optional[dict]:
        """
        Authenticate user by email and password.
        
        Returns user dict if valid, None otherwise.
        """
        return await self._authenticate_user("email", email, password)

    async def authenticate_by_name(self, name: str, password: str) -> Optional[dict]:
        """
        Authenticate user by name and password.
        
        Returns user dict if valid, None otherwise.
        """
        return await self._authenticate_user("name", name, password)

    async def authenticate_admin_by_email(self, email: str, password: str) -> Optional[dict]:
        """
        Authenticate admin by email and password.
        Checks email whitelist after successful password verification.
        
        Args:
            email: Admin email address
            password: Admin password
            
        Returns:
            Admin dict if valid and whitelisted, None otherwise
            
        Raises:
            HTTPException: If email is not whitelisted (403)
        """
        query = "SELECT * FROM admins WHERE email = $1 AND is_active = TRUE"
        admin = await self.db.read_one(query, email)

        if not admin:
            return None

        if not admin.get("password_hash") or not verify_password(password, admin["password_hash"]):
            return None

        # Check if email is whitelisted
        is_whitelisted = await admin_whitelist_service.check_email_whitelisted(email)
        if not is_whitelisted:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email is not whitelisted for admin access",
            )

        return admin

    # ================== Google OAuth ==================

    async def _make_http_request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        data: Optional[dict] = None,
    ) -> Optional[dict]:
        """
        Make HTTP request and return JSON response if successful.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            headers: Optional request headers
            data: Optional request data (for POST requests)
            
        Returns:
            JSON response dict if successful, None otherwise
        """
        try:
            async with httpx.AsyncClient() as client:
                if method.upper() == "GET":
                    response = await client.get(url, headers=headers or {})
                elif method.upper() == "POST":
                    response = await client.post(url, headers=headers or {}, data=data)
                else:
                    return None
                
                if response.status_code != 200:
                    return None
                
                return response.json()
        except Exception:
            return None

    async def verify_google_token(self, token: str) -> Optional[GoogleUserInfo]:
        """Verify Google OAuth token and get user info."""
        data = await self._make_http_request(
            "GET",
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        if not data:
            return None
        
        return GoogleUserInfo(
            id=data["sub"],
            email=data["email"],
            name=data.get("name", data["email"]),
            picture=data.get("picture"),
        )

    async def _find_or_create_oauth_user(
        self,
        email: str,
        name: str,
        photo_url: Optional[str] = None,
        google_id: Optional[str] = None,
        line_id: Optional[str] = None,
    ) -> dict:
        """
        Find existing user by email or create new OAuth user.
        Updates OAuth IDs if user exists but OAuth ID is missing.
        
        Args:
            email: User email
            name: User name
            photo_url: User photo URL
            google_id: Google OAuth ID (optional)
            line_id: LINE OAuth ID (optional)
            
        Returns:
            User dict
        """
        # Try to find user by email
        query = "SELECT * FROM users WHERE email = $1"
        user = await self.db.read_one(query, email)

        if user:
            # Update OAuth IDs and photo if not set
            updates = []
            params = []
            param_index = 1

            if google_id and not user.get("google_id"):
                updates.append(f"google_id = ${param_index}")
                params.append(google_id)
                param_index += 1
                user["google_id"] = google_id

            if line_id and not user.get("line_id"):
                updates.append(f"line_id = ${param_index}")
                params.append(line_id)
                param_index += 1
                user["line_id"] = line_id

            if photo_url and not user.get("photo_url"):
                updates.append(f"photo_url = ${param_index}")
                params.append(photo_url)
                param_index += 1
                user["photo_url"] = photo_url

            if updates:
                updates.append("updated_at = CURRENT_TIMESTAMP")
                update_query = f"""
                    UPDATE users 
                    SET {', '.join(updates)}
                    WHERE user_id = ${param_index}
                """
                params.append(user["user_id"])
                await self.db.execute(update_query, *params)

            return user
        else:
            # Create new user
            return await self._create_oauth_user(
                email=email,
                name=name,
                photo_url=photo_url,
                google_id=google_id,
                line_id=line_id,
            )

    async def authenticate_google_user(self, token: str) -> Optional[dict]:
        """
        Authenticate via Google OAuth.
        Creates user if not exists, updates google_id if needed.
        """
        google_info = await self.verify_google_token(token)
        if not google_info:
            return None

        return await self._find_or_create_oauth_user(
            email=google_info.email,
            name=google_info.name,
            photo_url=google_info.picture,
            google_id=google_info.id,
        )

    async def authenticate_admin_google(self, token: str) -> Optional[dict]:
        """
        Authenticate admin via Google OAuth.
        Checks email whitelist, creates admin if not exists, updates google_id if needed.
        
        Args:
            token: Google OAuth token
            
        Returns:
            Admin dict if authentication successful and email is whitelisted, None otherwise
            
        Raises:
            HTTPException: If email is not whitelisted (403) or Google token is invalid (401)
        """
        # Verify Google token
        google_info = await self.verify_google_token(token)
        if not google_info:
            return None

        # Check if email is whitelisted
        is_whitelisted = await admin_whitelist_service.check_email_whitelisted(google_info.email)
        if not is_whitelisted:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email is not whitelisted for admin access",
            )

        # Find or create admin
        return await admin_service._find_or_create_admin_google(
            email=google_info.email,
            name=google_info.name,
            google_id=google_info.id,
            photo_url=google_info.picture,
        )

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
        data = await self._make_http_request(
            "POST",
            "https://api.line.me/oauth2/v2.1/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": uri,
                "client_id": self.line_client_id,
                "client_secret": self.line_client_secret,
            },
        )
        
        return data.get("access_token") if data else None

    async def get_line_user_info(self, access_token: str) -> Optional[LineUserInfo]:
        """Get LINE user profile info."""
        data = await self._make_http_request(
            "GET",
            "https://api.line.me/v2/profile",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        if not data:
            return None
        
        return LineUserInfo(
            user_id=data["userId"],
            display_name=data["displayName"],
            picture_url=data.get("pictureUrl"),
            email=data.get("email"),
        )

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

        # Try to find user by line_id first
        query = "SELECT * FROM users WHERE line_id = $1"
        user = await self.db.read_one(query, line_info.user_id)
        if user:
            return user

        # Use email if available, otherwise create placeholder email
        email = line_info.email or f"{line_info.user_id}@line.placeholder"
        
        # Find or create user (will update line_id if user exists by email)
        return await self._find_or_create_oauth_user(
            email=email,
            name=line_info.display_name,
            photo_url=line_info.picture_url,
            line_id=line_info.user_id,
        )

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
        password_hash = hash_password_user(f"oauth_{user_id}_{dt.now(tz.utc).timestamp()}")

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

    async def create_session_from_request(
        self,
        request: Request,
        user_id: str,
    ) -> str:
        """
        Create a session for user from FastAPI Request object.
        Extracts IP address and user agent from request automatically.
        
        Args:
            request: FastAPI Request object
            user_id: User ID to create session for
            
        Returns:
            Session token string (to be set in cookie)
        """
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
        
        token, _ = await self.create_session(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        
        return token

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

    async def create_access_token_record(self, admin_id: str) -> tuple[str, AccessTokenData]:
        """
        Create a JWT access token and store hash in database.
        
        Returns (jwt_token, token_data) tuple.
        """
        jwt_token = create_access_token(admin_id)
        token_hash = hash_token(jwt_token)
        expires_at = get_token_expiry()

        token_data = AccessTokenData(
            admin_id=admin_id,
            token_hash=token_hash,
            expires_at=expires_at,
        )

        await self.db.insert_one("access_tokens", {
            "admin_id": token_data.admin_id,
            "token_hash": token_data.token_hash,
            "expires_at": token_data.expires_at,
        })

        return jwt_token, token_data

    async def validate_access_token(self, token: str) -> Optional[dict]:
        """
        Validate JWT access token and return admin if valid.
        """
        # First decode JWT
        payload = decode_access_token(token)
        if not payload:
            return None

        admin_id = payload.get("sub")
        if not admin_id:
            return None

        # Verify token exists in database and not expired
        token_hash = hash_token(token)
        query = """
            SELECT a.* FROM access_tokens t
            JOIN admins a ON t.admin_id = a.admin_id
            WHERE t.token_hash = $1 
            AND t.expires_at > CURRENT_TIMESTAMP
            AND a.is_active = TRUE
        """
        admin = await self.db.read_one(query, token_hash)
        return admin


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


async def get_current_admin_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> dict:
    """
    Dependency: Get current admin from JWT access token.
    Used for staff dashboard authentication.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    admin = await auth_service.validate_access_token(credentials.credentials)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return admin
