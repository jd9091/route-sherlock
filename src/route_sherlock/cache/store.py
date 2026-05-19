"""
Cache Store.

Simple caching interface for API responses. Two implementations:

- ``MemoryCache``: process-local, used by tests and short-lived runs.
- ``FileCache``: JSON files under ``~/.cache/route-sherlock/``, persistent
  across runs. Zero external dependencies; cache directory is human-readable
  and trivially clearable with ``rm -rf``.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class OfflineCacheMiss(Exception):
    """Raised when a collector running in offline mode has no cached entry."""


def default_cache_dir() -> Path:
    """Return the route-sherlock cache directory, honoring XDG_CACHE_HOME."""
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "route-sherlock"


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


class FileCache(Cache):
    """
    Persistent JSON-file cache under a directory (default
    ``~/.cache/route-sherlock``).

    Each entry is stored as a single JSON file whose name is the first 16
    hex chars of the sha256 of the cache key — keeping filenames bounded
    while remaining collision-resistant for the volumes route-sherlock
    deals with. The on-disk format is:

        {"key": "<original key>", "cached_at": <epoch>, "ttl": <s|null>, "value": ...}

    Writes are atomic (write-to-temp + rename) so a crash mid-write can't
    leave a half-written file in place.

    The directory is created lazily on first ``set``. Cache misses do not
    touch the filesystem.
    """

    def __init__(self, directory: Path | str | None = None):
        self.directory = Path(directory) if directory else default_cache_dir()

    def _path_for(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        return self.directory / f"{digest}.json"

    async def get(self, key: str) -> Any | None:
        path = self._path_for(key)
        if not path.exists():
            return None
        try:
            entry = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            # Corrupt or unreadable: treat as miss; don't crash the request.
            return None
        ttl = entry.get("ttl")
        if ttl is not None and time.time() > entry.get("cached_at", 0) + ttl:
            # Expired — best-effort cleanup, ignore failure.
            try:
                path.unlink()
            except OSError:
                pass
            return None
        return entry.get("value")

    async def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        payload = {
            "key": key,
            "cached_at": time.time(),
            "ttl": ttl,
            "value": value,
        }
        target = self._path_for(key)
        # Atomic write: temp file in same directory, then rename.
        fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", dir=self.directory)
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(payload, fh)
            os.replace(tmp_path, target)
        except Exception:
            # Clean up tmp if rename failed.
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    async def delete(self, key: str) -> None:
        path = self._path_for(key)
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    async def clear(self) -> None:
        if not self.directory.exists():
            return
        for path in self.directory.glob("*.json"):
            try:
                path.unlink()
            except OSError:
                pass

    @property
    def size(self) -> int:
        if not self.directory.exists():
            return 0
        return sum(1 for _ in self.directory.glob("*.json"))
