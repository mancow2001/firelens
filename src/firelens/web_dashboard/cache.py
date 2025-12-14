"""
FireLens Monitor - Simple Cache Module
TTL-based caching for reducing database queries
"""
import time
from typing import Any, Optional


class SimpleCache:
    """Simple TTL-based cache for dashboard data"""

    def __init__(self, ttl_seconds: int = 30):
        self.ttl = ttl_seconds
        self.cache: dict = {}
        self.timestamps: dict = {}

    def get(self, key: str) -> Optional[Any]:
        """Get cached value if not expired"""
        if key in self.cache:
            if time.time() - self.timestamps[key] < self.ttl:
                return self.cache[key]
            else:
                del self.cache[key]
                del self.timestamps[key]
        return None

    def set(self, key: str, value: Any) -> None:
        """Set cache value with current timestamp"""
        self.cache[key] = value
        self.timestamps[key] = time.time()

    def clear(self) -> None:
        """Clear all cache entries"""
        self.cache.clear()
        self.timestamps.clear()
