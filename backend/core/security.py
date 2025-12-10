"""
Shared Security Utilities

This module provides common security functions used across the application:
- Password hashing and verification
- ID generation (user_id, product_id, cart_id, order_id)
- Session token generation
- JWT token utilities
"""

import os
import random
import secrets
import string
import hashlib
from datetime import datetime as dt
from datetime import timedelta as td
from datetime import timezone as tz
from typing import Optional

from dotenv import load_dotenv
from jose import JWTError, jwt
import bcrypt as bcrypt_lib

load_dotenv("backend/.env")

# Bcrypt configuration
BCRYPT_ROUNDS_USER = 12
BCRYPT_ROUNDS_ADMIN = 14  # Higher security for admin accounts
BCRYPT_ROUNDS = BCRYPT_ROUNDS_USER  # Backward compatibility

# JWT Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

# Session Configuration
SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY", "your-session-secret-change-in-production")
SESSION_EXPIRE_DAYS = 7
SESSION_COOKIE_NAME = "session_token"


# ================== Password Utilities ==================

def hash_password_user(password: str) -> str:
    """Hash a password for users using bcrypt with user rounds."""
    password_bytes = password.encode('utf-8')
    salt = bcrypt_lib.gensalt(rounds=BCRYPT_ROUNDS_USER)
    hashed = bcrypt_lib.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def hash_password_admin(password: str) -> str:
    """Hash a password for admins using bcrypt with admin rounds (higher security)."""
    password_bytes = password.encode('utf-8')
    salt = bcrypt_lib.gensalt(rounds=BCRYPT_ROUNDS_ADMIN)
    hashed = bcrypt_lib.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')


def hash_password(password: str) -> str:
    """Hash a password using bcrypt (backward compatibility, uses user rounds)."""
    return hash_password_user(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash (works for both user and admin hashes)."""
    password_bytes = plain_password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt_lib.checkpw(password_bytes, hashed_bytes)


# ================== ID Generation ==================

def generate_user_id() -> str:
    """
    Generate a random 6-digit user ID.
    Format: 6 numeric characters (e.g., "123456")
    """
    return "".join(random.choices(string.digits, k=6))


def generate_admin_id() -> str:
    """
    Generate a random 6-digit admin ID.
    Format: 6 numeric characters (e.g., "123456")
    """
    return "".join(random.choices(string.digits, k=6))


def generate_product_id() -> str:
    """
    Generate a random product ID.
    Format: "pt_" + 6 alphanumeric characters (e.g., "pt_a1b2c3")
    """
    chars = string.ascii_lowercase + string.digits
    random_part = "".join(random.choices(chars, k=6))
    return f"pt_{random_part}"


def generate_cart_id() -> str:
    """
    Generate a random cart ID.
    Format: "ct_" + 6 alphanumeric characters (e.g., "ct_x1y2z3")
    """
    chars = string.ascii_lowercase + string.digits
    random_part = "".join(random.choices(chars, k=6))
    return f"ct_{random_part}"


def generate_order_id() -> str:
    """
    Generate a random 16-character order ID.
    Format: 16 alphanumeric characters (e.g., "a1b2c3d4e5f6g7h8")
    """
    chars = string.ascii_lowercase + string.digits
    return "".join(random.choices(chars, k=16))


# ================== Session Token Utilities ==================

def generate_session_token() -> str:
    """Generate a cryptographically secure session token."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """Hash a token for secure storage in database."""
    return hashlib.sha256(token.encode()).hexdigest()


def get_session_expiry() -> dt:
    """Get session expiry datetime."""
    return dt.now(tz.utc) + td(days=SESSION_EXPIRE_DAYS)


# ================== JWT Token Utilities ==================

def create_access_token(user_id: str, expires_delta: Optional[td] = None) -> str:
    """
    Create a JWT access token for staff dashboard authentication.
    
    Args:
        user_id: The user ID to encode in the token
        expires_delta: Optional custom expiry time
        
    Returns:
        Encoded JWT token string
    """
    if expires_delta:
        expire = dt.now(tz.utc) + expires_delta
    else:
        expire = dt.now(tz.utc) + td(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {
        "sub": user_id,
        "exp": expire,
        "iat": dt.now(tz.utc),
    }
    
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    """
    Decode and validate a JWT access token.
    
    Args:
        token: The JWT token to decode
        
    Returns:
        Decoded payload dict or None if invalid
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        return None


def get_token_expiry() -> dt:
    """Get access token expiry datetime."""
    return dt.now(tz.utc) + td(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

