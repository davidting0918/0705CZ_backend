"""
Admin Whitelist Service - Check if email is whitelisted for admin access

Note: Whitelist CRUD operations are managed manually via database.
This service only provides the check functionality used during authentication.
"""

from backend.core.db_manager import get_db


class AdminWhitelistService:
    """Service for checking admin email whitelist status."""

    @property
    def db(self):
        """Get database client from global manager."""
        return get_db()

    async def check_email_whitelisted(self, email: str) -> bool:
        """
        Check if email is in the whitelist.

        Args:
            email: Email address to check

        Returns:
            True if email is whitelisted, False otherwise
        """
        query = "SELECT 1 FROM admin_whitelist WHERE email = $1"
        result = await self.db.read_one(query, email)
        return result is not None


# Global whitelist service instance
admin_whitelist_service = AdminWhitelistService()
