"""
Rate Limiting Module

Provides rate limiting functionality using slowapi to protect public endpoints
from abuse and excessive requests.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# Create rate limiter instance
# Uses client IP address as the key for rate limiting
limiter = Limiter(key_func=get_remote_address)
