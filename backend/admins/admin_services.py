"""
Admin Services - Business logic for admin operations
"""

from datetime import datetime as dt
from datetime import timezone as tz
from typing import Optional

from backend.core.db_manager import get_db
from backend.core.security import generate_admin_id, hash_password_admin
from backend.admins.admin_models import (
    AdminCreate,
    AdminProfileResponse,
    AdminPublicResponse,
    AdminRegisterRequest,
    AdminResponse,
    AdminUpdateRequest,
)


class AdminService:
    """Admin service handling admin operations."""

    @property
    def db(self):
        """Get database client from global manager."""
        return get_db()

    # ================== Response Builders ==================

    def _build_admin_profile_response(self, admin: dict) -> AdminProfileResponse:
        """Build AdminProfileResponse from admin dict."""
        return AdminProfileResponse(
            admin_id=admin["admin_id"],
            email=admin["email"],
            name=admin["name"],
            phone=admin.get("phone"),
            photo_url=admin.get("photo_url"),
            is_active=admin["is_active"],
            created_at=admin["created_at"],
            updated_at=admin["updated_at"],
        )

    def _build_admin_public_response(self, admin: dict) -> AdminPublicResponse:
        """Build AdminPublicResponse from admin dict."""
        return AdminPublicResponse(
            admin_id=admin["admin_id"],
            name=admin["name"],
            photo_url=admin.get("photo_url"),
        )

    def build_admin_response(
        self,
        admin: dict,
        message: str = "Admin retrieved",
    ) -> AdminResponse:
        """Build complete AdminResponse wrapper."""
        return AdminResponse(
            status=1,
            message=message,
            data=self._build_admin_profile_response(admin),
        )

    def build_admin_public_dict(
        self,
        admin: dict,
        message: str = "Admin retrieved",
    ) -> dict:
        """Build public admin response as dict (for rate-limited endpoints)."""
        return {
            "status": 1,
            "message": message,
            "data": self._build_admin_public_response(admin).model_dump(),
        }

    # ================== Admin CRUD ==================

    async def get_admin_by_id(self, admin_id: str) -> Optional[dict]:
        """Get admin by admin_id."""
        query = "SELECT * FROM admins WHERE admin_id = $1 AND is_active = TRUE"
        return await self.db.read_one(query, admin_id)

    async def get_admin_by_id_response(self, admin_id: str) -> dict:
        """
        Get admin by ID and return formatted response.
        
        Raises ValueError if admin not found.
        """
        admin = await self.get_admin_by_id(admin_id)
        if not admin:
            raise ValueError("Admin not found")
        return self.build_admin_public_dict(admin, "Admin retrieved")

    async def get_admin_by_email(self, email: str) -> Optional[dict]:
        """Get admin by email."""
        query = "SELECT * FROM admins WHERE email = $1"
        return await self.db.read_one(query, email)

    async def create_admin(self, request: AdminRegisterRequest) -> dict:
        """
        Create a new admin from registration request.
        
        Raises ValueError if email already exists.
        """
        # Check if email already exists
        existing = await self.get_admin_by_email(request.email)
        if existing:
            raise ValueError("Email already registered")

        # Generate unique admin_id
        admin_id = generate_admin_id()
        while await self.db.read_one("SELECT 1 FROM admins WHERE admin_id = $1", admin_id):
            admin_id = generate_admin_id()

        # Create admin
        now = dt.now(tz.utc)
        admin_data = AdminCreate(
            admin_id=admin_id,
            email=request.email,
            name=request.name,
            password_hash=hash_password_admin(request.password),
            phone=request.phone,
            photo_url=request.photo_url,
            is_active=True,
            created_at=now,
            updated_at=now,
        )

        await self.db.insert_one("admins", admin_data.model_dump())

        # Return created admin (without password_hash)
        return await self.get_admin_by_id(admin_id)

    async def create_admin_response(self, request: AdminRegisterRequest) -> AdminResponse:
        """
        Create a new admin and return formatted response.
        
        Raises ValueError if email already exists.
        """
        admin = await self.create_admin(request)
        return self.build_admin_response(admin, "Admin registered successfully")

    def build_admin_profile_from_dict(self, admin_dict: dict) -> AdminResponse:
        """Build AdminResponse from admin dict (for authenticated endpoints)."""
        return self.build_admin_response(admin_dict, "Admin profile retrieved")

    async def update_admin(self, admin_id: str, request: AdminUpdateRequest) -> Optional[dict]:
        """Update admin profile."""
        # Build update query dynamically based on provided fields
        updates = []
        values = []
        param_count = 0

        if request.name is not None:
            param_count += 1
            updates.append(f"name = ${param_count}")
            values.append(request.name)

        if request.phone is not None:
            param_count += 1
            updates.append(f"phone = ${param_count}")
            values.append(request.phone)

        if request.photo_url is not None:
            param_count += 1
            updates.append(f"photo_url = ${param_count}")
            values.append(request.photo_url)

        if not updates:
            return await self.get_admin_by_id(admin_id)

        # Add updated_at
        param_count += 1
        updates.append(f"updated_at = ${param_count}")
        values.append(dt.now(tz.utc))

        # Add admin_id for WHERE clause
        param_count += 1
        values.append(admin_id)

        query = f"""
            UPDATE admins 
            SET {', '.join(updates)}
            WHERE admin_id = ${param_count}
            RETURNING *
        """

        result = await self.db.execute_returning(query, *values)
        return result

    async def list_admins(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """
        List admins with pagination.
        
        Returns (admins, total_count) tuple.
        """
        # Get total count
        count_query = "SELECT COUNT(*) as count FROM admins WHERE is_active = TRUE"
        count_result = await self.db.read_one(count_query)
        total = count_result["count"] if count_result else 0

        # Get admins
        query = """
            SELECT admin_id, name, photo_url
            FROM admins 
            WHERE is_active = TRUE
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
        """
        admins = await self.db.read(query, limit, offset)

        return admins, total

    async def check_email_available(self, email: str) -> bool:
        """Check if email is available for registration."""
        existing = await self.get_admin_by_email(email)
        return existing is None


# Global admin service instance
admin_service = AdminService()
