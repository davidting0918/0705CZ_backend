"""
User Services - Business logic for user operations
"""

from datetime import datetime as dt
from datetime import timezone as tz
from typing import Optional

from backend.core.db_manager import get_db
from backend.core.security import generate_user_id, hash_password
from backend.users.user_models import UserCreate, UserRegisterRequest, UserUpdateRequest


class UserService:
    """User service handling user operations."""

    @property
    def db(self):
        """Get database client from global manager."""
        return get_db()

    # ================== User CRUD ==================

    async def get_user_by_id(self, user_id: str) -> Optional[dict]:
        """Get user by user_id."""
        query = "SELECT * FROM users WHERE user_id = $1 AND is_active = TRUE"
        return await self.db.read_one(query, user_id)

    async def get_user_by_email(self, email: str) -> Optional[dict]:
        """Get user by email."""
        query = "SELECT * FROM users WHERE email = $1"
        return await self.db.read_one(query, email)

    async def create_user(self, request: UserRegisterRequest) -> dict:
        """
        Create a new user from registration request.
        
        Raises ValueError if email already exists.
        """
        # Check if email already exists
        existing = await self.get_user_by_email(request.email)
        if existing:
            raise ValueError("Email already registered")

        # Generate unique user_id
        user_id = generate_user_id()
        while await self.db.read_one("SELECT 1 FROM users WHERE user_id = $1", user_id):
            user_id = generate_user_id()

        # Create user
        now = dt.now(tz.utc)
        user_data = UserCreate(
            user_id=user_id,
            email=request.email,
            name=request.name,
            password_hash=hash_password(request.password),
            phone=request.phone,
            address=request.address,
            is_active=True,
            is_verified=False,
            created_at=now,
            updated_at=now,
        )

        await self.db.insert_one("users", user_data.model_dump())

        # Return created user (without password_hash)
        return await self.get_user_by_id(user_id)

    async def update_user(self, user_id: str, request: UserUpdateRequest) -> Optional[dict]:
        """Update user profile."""
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

        if request.address is not None:
            param_count += 1
            updates.append(f"address = ${param_count}")
            values.append(request.address)

        if request.photo_url is not None:
            param_count += 1
            updates.append(f"photo_url = ${param_count}")
            values.append(request.photo_url)

        if not updates:
            return await self.get_user_by_id(user_id)

        # Add updated_at
        param_count += 1
        updates.append(f"updated_at = ${param_count}")
        values.append(dt.now(tz.utc))

        # Add user_id for WHERE clause
        param_count += 1
        values.append(user_id)

        query = f"""
            UPDATE users 
            SET {', '.join(updates)}
            WHERE user_id = ${param_count}
            RETURNING *
        """

        result = await self.db.execute_returning(query, *values)
        return result

    async def list_users(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """
        List users with pagination.
        
        Returns (users, total_count) tuple.
        """
        # Get total count
        count_query = "SELECT COUNT(*) as count FROM users WHERE is_active = TRUE"
        count_result = await self.db.read_one(count_query)
        total = count_result["count"] if count_result else 0

        # Get users
        query = """
            SELECT user_id, name, photo_url
            FROM users 
            WHERE is_active = TRUE
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
        """
        users = await self.db.read(query, limit, offset)

        return users, total

    async def check_email_available(self, email: str) -> bool:
        """Check if email is available for registration."""
        existing = await self.get_user_by_email(email)
        return existing is None


# Global user service instance
user_service = UserService()

