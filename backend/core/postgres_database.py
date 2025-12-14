"""
PostgreSQL Async Database Client

This module provides an async PostgreSQL client with connection pooling,
query methods, and proper event loop handling for use across different
execution contexts (main app, tests, etc.).
"""

import asyncio
from contextlib import asynccontextmanager
from decimal import Decimal
from typing import Any, Dict, List, Optional

import asyncpg
from asyncpg import Pool

from backend.core.environment import get_database_connection_string


class PostgresAsyncClient:
    """Async PostgreSQL client with connection pooling."""

    def __init__(self, environment: Optional[str] = None):
        """
        Initialize PostgreSQL async client with environment support.

        Args:
            environment (str, optional): Environment name (test, staging, prod).
                                        If None, auto-detect from environment variables.
        """
        self.environment = environment
        self.connection_string = get_database_connection_string(environment)

        self._pool: Optional[Pool] = None
        self._init_lock: Optional[asyncio.Lock] = None  # Lazy initialization of lock
        self._pool_loop_id: Optional[int] = None  # Track which event loop the pool was created in

    def _get_init_lock(self) -> asyncio.Lock:
        """Get or create the initialization lock (lazy initialization)"""
        if self._init_lock is None:
            self._init_lock = asyncio.Lock()
        return self._init_lock

    def _is_pool_valid(self) -> bool:
        """Check if the pool exists and is bound to the current event loop"""
        if self._pool is None:
            return False
        try:
            # Check if pool is bound to current event loop
            current_loop = asyncio.get_running_loop()
            current_loop_id = id(current_loop)
            # Check if pool was created in a different event loop
            if self._pool_loop_id is not None and self._pool_loop_id != current_loop_id:
                return False
            # Also check if pool is closing
            return not self._pool.is_closing()
        except RuntimeError:
            # No running loop - pool might be invalid
            return False

    async def init_pool(self):
        """Initialize connection pool (async-safe, event-loop aware)"""
        # Check if pool exists and is valid for current event loop
        if self._is_pool_valid():
            return

        # Acquire lock to ensure only one coroutine initializes the pool
        async with self._get_init_lock():
            # Double-check after acquiring lock
            if self._is_pool_valid():
                return

            # Close existing pool if it exists but is invalid
            if self._pool is not None:
                try:
                    await self._pool.close()
                except Exception:
                    pass  # Ignore errors when closing invalid pool
                self._pool = None
                self._pool_loop_id = None

            # Create the pool in the current event loop
            current_loop = asyncio.get_running_loop()
            self._pool = await asyncpg.create_pool(
                self.connection_string,
                min_size=1,
                max_size=50,
                command_timeout=60,
                statement_cache_size=0,  # Disable statement caching to avoid InvalidCachedStatementError
            )
            # Store the event loop ID for validation
            self._pool_loop_id = id(current_loop)

    async def close(self):
        """Close the database connection pool"""
        if self._init_lock:
            async with self._get_init_lock():
                if self._pool:
                    await self._pool.close()
                    self._pool = None
                    self._pool_loop_id = None
        else:
            # No lock means pool was never initialized, nothing to close
            if self._pool:
                await self._pool.close()
                self._pool = None
                self._pool_loop_id = None

    @asynccontextmanager
    async def get_connection(self):
        """Get a database connection from the pool (auto-initializes if needed)"""
        # Ensure pool is initialized in current event loop
        await self.init_pool()

        if not self._pool or not self._is_pool_valid():
            raise RuntimeError("Failed to initialize database connection pool")

        # Acquire a connection from the pool
        # Each call to acquire() gets a separate connection, preventing conflicts
        try:
            async with self._pool.acquire() as connection:
                yield connection
        except (RuntimeError, asyncpg.exceptions.InterfaceError) as e:
            # If we get a "different loop" error or "another operation is in progress"
            # due to event loop mismatch, try to recreate the pool
            error_msg = str(e).lower()
            if (
                "different loop" in error_msg
                or "attached to a different" in error_msg
                or ("another operation is in progress" in error_msg and self._pool_loop_id is not None)
            ):
                # Check if we're actually in a different loop
                try:
                    current_loop_id = id(asyncio.get_running_loop())
                    if self._pool_loop_id != current_loop_id:
                        # Close and recreate pool in current loop
                        async with self._get_init_lock():
                            if self._pool:
                                try:
                                    await self._pool.close()
                                except Exception:
                                    pass
                                self._pool = None
                                self._pool_loop_id = None
                            # Recreate in current loop
                            current_loop = asyncio.get_running_loop()
                            self._pool = await asyncpg.create_pool(
                                self.connection_string,
                                min_size=1,
                                max_size=50,
                                command_timeout=60,
                                statement_cache_size=0,
                            )
                            self._pool_loop_id = id(current_loop)
                        # Retry acquiring connection
                        async with self._pool.acquire() as connection:
                            yield connection
                        return
                except Exception:
                    pass  # Fall through to re-raise original error
            # Re-raise if we couldn't handle it
            raise

    # ================== Data Conversion Helpers ==================

    def _convert_decimals_to_floats(self, obj: Any) -> Any:
        """
        Recursively convert all Decimal instances to float in nested data structures.

        Args:
            obj: The object to convert (dict, list, tuple, Decimal, or any other type)

        Returns:
            The object with all Decimal values converted to float
        """
        if isinstance(obj, Decimal):
            return float(obj)
        elif isinstance(obj, dict):
            return {key: self._convert_decimals_to_floats(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_decimals_to_floats(item) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(self._convert_decimals_to_floats(item) for item in obj)
        else:
            return obj

    # ================== Simple Query Methods ==================

    async def read(self, query: str, *args: Any) -> List[Dict[str, Any]]:
        """
        Execute a SELECT query and return results as list of dictionaries

        Args:
            query (str): SQL SELECT query with $1, $2, etc. placeholders
            *args: Parameters for the query placeholders

        Returns:
            List[Dict[str, Any]]: Query results as list of dictionaries with Decimal values converted to float
        """
        try:
            async with self.get_connection() as conn:
                rows = await conn.fetch(query, *args)
                result = [dict(row) for row in rows]
                return self._convert_decimals_to_floats(result)
        except Exception as e:
            raise e

    async def read_one(self, query: str, *args: Any) -> Optional[Dict[str, Any]]:
        """
        Execute a SELECT query and return first result as dictionary

        Args:
            query (str): SQL SELECT query with $1, $2, etc. placeholders
            *args: Parameters for the query placeholders

        Returns:
            Optional[Dict[str, Any]]:
                First query result as dictionary with Decimal values converted to float,
                or None if no result
        """
        try:
            async with self.get_connection() as conn:
                row = await conn.fetchrow(query, *args)
                if row:
                    result = dict(row)
                    return self._convert_decimals_to_floats(result)
                return None
        except Exception as e:
            raise e

    async def insert_one(self, table: str, data: Dict[str, Any]) -> Any:
        """
        Insert a single record into a table

        Args:
            table (str): Table name
            data (Dict[str, Any]): Dictionary with column names as keys and values to insert

        Returns:
            Any: The ID of the inserted record (if table has 'id' column), or the full inserted record
        """
        try:
            columns = list(data.keys())
            placeholders = [f"${i}" for i in range(1, len(columns) + 1)]
            values = list(data.values())

            # Try to return 'id' if it exists, otherwise return all columns
            query = f"""
                INSERT INTO {table} ({', '.join(columns)})
                VALUES ({', '.join(placeholders)})
                RETURNING *
            """

            async with self.get_connection() as conn:
                result = await conn.fetchrow(query, *values)
                result_dict = dict(result)

                # Convert Decimal values to float
                result_dict = self._convert_decimals_to_floats(result_dict)

                # Return just the id if it exists, otherwise return the full record
                return result_dict.get("id", result_dict)

        except Exception as e:
            raise e

    async def insert(self, table: str, data: List[Dict[str, Any]]) -> List[Any]:
        """
        Insert multiple records into a table

        Args:
            table (str): Table name
            data (List[Dict[str, Any]]): List of dictionaries with column names as keys and values to insert

        Returns:
            List[Any]: List of inserted record IDs (if table has 'id' column), or list of full inserted records
        """
        try:
            if not data:
                return []

            # Use the first record to determine columns
            columns = list(data[0].keys())

            # Build the query with multiple value sets
            placeholders_per_row = len(columns)
            value_sets = []
            all_values = []

            for i, record in enumerate(data):
                # Ensure all records have the same columns
                if set(record.keys()) != set(columns):
                    raise ValueError(
                        f"All records must have the same columns. Expected: {columns}, Got: {list(record.keys())}"
                    )

                # Create placeholders for this row
                row_placeholders = [f"${j + i * placeholders_per_row + 1}" for j in range(placeholders_per_row)]
                value_sets.append(f"({', '.join(row_placeholders)})")

                # Add values in the same order as columns
                for col in columns:
                    all_values.append(record[col])

            query = f"""
                INSERT INTO {table} ({', '.join(columns)})
                VALUES {', '.join(value_sets)}
                RETURNING *
            """

            async with self.get_connection() as conn:
                results = await conn.fetch(query, *all_values)
                result_dicts = [dict(row) for row in results]

                # Convert Decimal values to float
                result_dicts = self._convert_decimals_to_floats(result_dicts)

                # Return just the ids if they exist, otherwise return the full records
                if result_dicts and "id" in result_dicts[0]:
                    return [record["id"] for record in result_dicts]
                else:
                    return result_dicts

        except Exception as e:
            raise e

    async def execute(self, query: str, *args: Any) -> str:
        """
        Execute an INSERT, UPDATE, or DELETE query

        Args:
            query (str): SQL query with $1, $2, etc. placeholders
            *args: Parameters for the query placeholders

        Returns:
            str: Result status from the database (e.g., "INSERT 0 1", "UPDATE 1", "DELETE 1")
        """
        async with self.get_connection() as conn:
            result = await conn.execute(query, *args)
            return result

    async def execute_returning(self, query: str, *args: Any) -> Any:
        """
        Execute an INSERT, UPDATE, or DELETE query with RETURNING clause

        Args:
            query (str): SQL query with RETURNING clause and $1, $2, etc. placeholders
            *args: Parameters for the query placeholders

        Returns:
            Any: The returned value from the RETURNING clause with Decimal values converted to float
        """
        async with self.get_connection() as conn:
            result = await conn.fetchrow(query, *args)
            if result:
                result_dict = dict(result)
                return self._convert_decimals_to_floats(result_dict)
            return None
