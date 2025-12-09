"""
Product Services - Business logic for product operations
"""

from datetime import datetime as dt
from datetime import timezone as tz
from typing import Optional

from backend.core.db_manager import get_db
from backend.core.security import generate_product_id
from backend.products.product_models import (
    ProductCreate,
    ProductCreateRequest,
    ProductUpdateRequest,
)


class ProductService:
    """Product service handling product operations."""

    @property
    def db(self):
        """Get database client from global manager."""
        return get_db()

    # ================== Product CRUD ==================

    async def get_product_by_id(self, product_id: str) -> Optional[dict]:
        """Get product by product_id."""
        query = "SELECT * FROM products WHERE product_id = $1"
        return await self.db.read_one(query, product_id)

    async def get_product_by_sku(self, product_sku: str) -> Optional[dict]:
        """Get product by SKU."""
        query = "SELECT * FROM products WHERE product_sku = $1"
        return await self.db.read_one(query, product_sku)

    async def create_product(self, request: ProductCreateRequest) -> dict:
        """
        Create a new product.
        
        Raises ValueError if SKU already exists.
        """
        # Check if SKU already exists
        existing = await self.get_product_by_sku(request.product_sku)
        if existing:
            raise ValueError("Product SKU already exists")

        # Generate unique product_id
        product_id = generate_product_id()
        while await self.db.read_one("SELECT 1 FROM products WHERE product_id = $1", product_id):
            product_id = generate_product_id()

        # Create product
        now = dt.now(tz.utc)
        product_data = ProductCreate(
            product_id=product_id,
            product_sku=request.product_sku,
            name=request.name,
            description=request.description,
            currency=request.currency,
            price=request.price,
            qty=request.qty,
            photo_url=request.photo_url,
            category=request.category,
            is_active=request.is_active,
            created_at=now,
            updated_at=now,
        )

        await self.db.insert_one("products", product_data.model_dump())

        # Return created product
        return await self.get_product_by_id(product_id)

    async def update_product(
        self,
        product_id: str,
        request: ProductUpdateRequest,
    ) -> Optional[dict]:
        """Update product details."""
        # Build update query dynamically based on provided fields
        updates = []
        values = []
        param_count = 0

        if request.name is not None:
            param_count += 1
            updates.append(f"name = ${param_count}")
            values.append(request.name)

        if request.description is not None:
            param_count += 1
            updates.append(f"description = ${param_count}")
            values.append(request.description)

        if request.currency is not None:
            param_count += 1
            updates.append(f"currency = ${param_count}")
            values.append(request.currency)

        if request.price is not None:
            param_count += 1
            updates.append(f"price = ${param_count}")
            values.append(request.price)

        if request.qty is not None:
            param_count += 1
            updates.append(f"qty = ${param_count}")
            values.append(request.qty)

        if request.photo_url is not None:
            param_count += 1
            updates.append(f"photo_url = ${param_count}")
            values.append(request.photo_url)

        if request.category is not None:
            param_count += 1
            updates.append(f"category = ${param_count}")
            values.append(request.category)

        if request.is_active is not None:
            param_count += 1
            updates.append(f"is_active = ${param_count}")
            values.append(request.is_active)

        if not updates:
            return await self.get_product_by_id(product_id)

        # Add updated_at
        param_count += 1
        updates.append(f"updated_at = ${param_count}")
        values.append(dt.now(tz.utc))

        # Add product_id for WHERE clause
        param_count += 1
        values.append(product_id)

        query = f"""
            UPDATE products 
            SET {', '.join(updates)}
            WHERE product_id = ${param_count}
            RETURNING *
        """

        result = await self.db.execute_returning(query, *values)
        return result

    async def list_products(
        self,
        category: Optional[str] = None,
        is_active: Optional[bool] = True,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """
        List products with filtering and pagination.
        
        Returns (products, total_count) tuple.
        """
        # Build WHERE clause
        conditions = []
        values = []
        param_count = 0

        if is_active is not None:
            param_count += 1
            conditions.append(f"is_active = ${param_count}")
            values.append(is_active)

        if category:
            param_count += 1
            conditions.append(f"category = ${param_count}")
            values.append(category)

        where_clause = ""
        if conditions:
            where_clause = "WHERE " + " AND ".join(conditions)

        # Get total count
        count_query = f"SELECT COUNT(*) as count FROM products {where_clause}"
        count_result = await self.db.read_one(count_query, *values)
        total = count_result["count"] if count_result else 0

        # Get products
        param_count += 1
        limit_param = param_count
        param_count += 1
        offset_param = param_count
        values.extend([limit, offset])

        query = f"""
            SELECT product_id, product_sku, name, price, qty, photo_url, category, is_active
            FROM products 
            {where_clause}
            ORDER BY created_at DESC
            LIMIT ${limit_param} OFFSET ${offset_param}
        """
        products = await self.db.read(query, *values)

        return products, total

    async def get_categories(self) -> list[str]:
        """Get list of unique product categories."""
        query = """
            SELECT DISTINCT category 
            FROM products 
            WHERE is_active = TRUE 
            ORDER BY category
        """
        results = await self.db.read(query)
        return [r["category"] for r in results]


# Global product service instance
product_service = ProductService()

