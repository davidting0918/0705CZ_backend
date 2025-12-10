"""
Product Services - Business logic for product operations
"""

from datetime import datetime as dt
from datetime import timezone as tz
from typing import Optional

from backend.core.db_manager import get_db
from backend.core.security import generate_product_id
from backend.products.product_models import (
    CategoryListResponse,
    ProductCreate,
    ProductCreateRequest,
    ProductListItemResponse,
    ProductListResponse,
    ProductResponse,
    ProductUpdateRequest,
    SingleProductResponse,
)


class ProductService:
    """Product service handling product operations."""

    @property
    def db(self):
        """Get database client from global manager."""
        return get_db()

    # ================== Response Builders ==================

    def _build_product_response(self, product: dict) -> ProductResponse:
        """Build ProductResponse from product dict."""
        return ProductResponse(
            product_id=product["product_id"],
            product_sku=product["product_sku"],
            name=product["name"],
            description=product.get("description"),
            currency=product["currency"],
            price=product["price"],
            qty=product["qty"],
            photo_url=product.get("photo_url"),
            category=product["category"],
            is_active=product["is_active"],
            created_at=product["created_at"],
            updated_at=product["updated_at"],
        )

    def _build_product_list_item_response(self, product: dict) -> ProductListItemResponse:
        """Build ProductListItemResponse from product dict."""
        return ProductListItemResponse(
            product_id=product["product_id"],
            product_sku=product["product_sku"],
            name=product["name"],
            price=product["price"],
            qty=product["qty"],
            photo_url=product.get("photo_url"),
            category=product["category"],
            is_active=product["is_active"],
        )

    def build_single_product_response(
        self,
        product: dict,
        message: str = "Product retrieved",
    ) -> SingleProductResponse:
        """Build complete SingleProductResponse wrapper."""
        return SingleProductResponse(
            status=1,
            message=message,
            data=self._build_product_response(product),
        )

    def build_product_list_response(
        self,
        products: list[dict],
        total: int,
        limit: int,
        offset: int,
        message: str = "Products retrieved",
    ) -> ProductListResponse:
        """Build complete ProductListResponse wrapper."""
        return ProductListResponse(
            status=1,
            message=message,
            data=[self._build_product_list_item_response(p) for p in products],
            total=total,
            limit=limit,
            offset=offset,
        )

    def build_category_list_response(
        self,
        categories: list[str],
        message: str = "Categories retrieved",
    ) -> CategoryListResponse:
        """Build complete CategoryListResponse wrapper."""
        return CategoryListResponse(
            status=1,
            message=message,
            data=categories,
        )

    # ================== Product CRUD ==================

    async def get_product_by_id(self, product_id: str) -> Optional[dict]:
        """Get product by product_id."""
        query = "SELECT * FROM products WHERE product_id = $1"
        return await self.db.read_one(query, product_id)

    async def get_product_by_id_response(self, product_id: str) -> SingleProductResponse:
        """
        Get product by ID and return formatted response.
        
        Raises ValueError if product not found.
        """
        product = await self.get_product_by_id(product_id)
        if not product:
            raise ValueError("Product not found")
        return self.build_single_product_response(product, "Product retrieved")

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

    async def create_product_response(self, request: ProductCreateRequest) -> SingleProductResponse:
        """
        Create a new product and return formatted response.
        
        Raises ValueError if SKU already exists.
        """
        product = await self.create_product(request)
        return self.build_single_product_response(product, "Product created successfully")

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

    async def list_products_response(
        self,
        category: Optional[str] = None,
        is_active: Optional[bool] = True,
        limit: int = 50,
        offset: int = 0,
    ) -> ProductListResponse:
        """
        List products with filtering and pagination, returning formatted response.
        """
        products, total = await self.list_products(category, is_active, limit, offset)
        return self.build_product_list_response(products, total, limit, offset, "Products retrieved")

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

    async def get_categories_response(self) -> CategoryListResponse:
        """Get list of unique product categories, returning formatted response."""
        categories = await self.get_categories()
        return self.build_category_list_response(categories, "Categories retrieved")


# Global product service instance
product_service = ProductService()

