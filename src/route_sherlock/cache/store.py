"""
Cache Store.

Simple caching interface for API responses.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any


class Cache(ABC):
    """Abstract base class for cache implementations."""

    @abstractmethod
    async def get(self, key: str) -> Any | None:
        """Get a value from cache."""
        pass

    @abstractmethod
    async def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Set a value in cache with optional TTL."""
        pass

    @abstractmethod
    async def delete(self, key: str) -> None:
        """Delete a value from cache."""
        pass

    @abstractmethod
    async def clear(self) -> None:
        """Clear all cached values."""
        pass


class MemoryCache(Cache):
    """
    Simple in-memory cache implementation.

    Thread-safe for async usage within a single event loop.

    Example:
        cache = MemoryCache()
        await cache.set("key", {"data": "value"}, ttl=3600)
        data = await cache.get("key")
    """

    def __init__(self):
        self._store: dict[str, tuple[Any, float | None]] = {}

    async def get(self, key: str) -> Any | None:
        """Get a value from cache, respecting TTL."""
        if key not in self._store:
            return None

        value, expires_at = self._store[key]

        if expires_at is not None and time.time() > expires_at:
            del self._store[key]
            return None

        return value

    async def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Set a value in cache with optional TTL in seconds."""
        expires_at = time.time() + ttl if ttl else None
        self._store[key] = (value, expires_at)

    async def delete(self, key: str) -> None:
        """Delete a value from cache."""
        self._store.pop(key, None)

    async def clear(self) -> None:
        """Clear all cached values."""
        self._store.clear()

    def cleanup_expired(self) -> int:
        """Remove expired entries and return count removed."""
        now = time.time()
        expired = [
            key for key, (_, expires_at) in self._store.items()
            if expires_at is not None and now > expires_at
        ]
        for key in expired:
            del self._store[key]
        return len(expired)

    @property
    def size(self) -> int:
        """Return number of cached items."""
        return len(self._store)
