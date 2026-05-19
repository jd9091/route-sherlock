"""Tests for the FileCache (persistent JSON cache)."""
from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import pytest

from route_sherlock.cache.store import (
    FileCache,
    OfflineCacheMiss,
    default_cache_dir,
)


@pytest.fixture
def cache(tmp_path: Path) -> FileCache:
    return FileCache(directory=tmp_path / "rs-cache")


async def test_set_then_get_roundtrips_value(cache: FileCache):
    await cache.set("k", {"hello": "world", "n": 42})
    assert await cache.get("k") == {"hello": "world", "n": 42}


async def test_miss_returns_none_and_does_not_create_directory(tmp_path: Path):
    c = FileCache(directory=tmp_path / "never-created")
    assert await c.get("anything") is None
    assert not (tmp_path / "never-created").exists()


async def test_ttl_expires_entry(cache: FileCache):
    await cache.set("k", "v", ttl=0)  # already-expired
    # Force at least 1s clock movement so floats compare correctly.
    await asyncio.sleep(0.01)
    assert await cache.get("k") is None


async def test_no_ttl_means_never_expires(cache: FileCache):
    await cache.set("k", "v")  # ttl=None
    await asyncio.sleep(0.01)
    assert await cache.get("k") == "v"


async def test_delete_removes_entry(cache: FileCache):
    await cache.set("k", "v")
    await cache.delete("k")
    assert await cache.get("k") is None


async def test_clear_removes_all_entries(cache: FileCache):
    await cache.set("a", 1)
    await cache.set("b", 2)
    await cache.clear()
    assert cache.size == 0


async def test_size_counts_only_entries(cache: FileCache):
    assert cache.size == 0
    await cache.set("a", 1)
    await cache.set("b", 2)
    assert cache.size == 2


async def test_corrupt_file_is_treated_as_miss(cache: FileCache):
    await cache.set("k", "good")
    path = cache._path_for("k")
    path.write_text("not valid json {{{")
    assert await cache.get("k") is None  # graceful, no exception


async def test_atomic_write_does_not_leak_tmp_file(cache: FileCache):
    await cache.set("k", "v")
    leftovers = [p for p in cache.directory.iterdir() if p.name.startswith(".tmp-")]
    assert leftovers == []


def test_default_cache_dir_respects_xdg(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert default_cache_dir() == tmp_path / "xdg" / "route-sherlock"


def test_default_cache_dir_fallback(monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "fakehome")
    assert default_cache_dir() == tmp_path / "fakehome" / ".cache" / "route-sherlock"


def test_offline_cache_miss_is_exception():
    # Smoke: importable and constructible with a message.
    e = OfflineCacheMiss("no cached entry")
    assert "no cached entry" in str(e)
