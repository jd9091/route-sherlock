"""Unit tests for the RIPEstat retry/backoff helper."""
from __future__ import annotations

from route_sherlock.collectors.ripestat import RIPEstatClient


def test_retry_delay_uses_retry_after_header():
    d = RIPEstatClient._retry_delay(attempt=0, retry_after="7")
    assert 7.0 <= d <= 7.5


def test_retry_delay_falls_back_to_exponential():
    d2 = RIPEstatClient._retry_delay(attempt=2)
    assert 4.0 <= d2 <= 4.5


def test_retry_delay_is_capped_at_30_seconds():
    d = RIPEstatClient._retry_delay(attempt=10)
    assert 30.0 <= d <= 30.5


def test_retry_delay_ignores_garbage_retry_after():
    d = RIPEstatClient._retry_delay(attempt=1, retry_after="soon")
    assert 2.0 <= d <= 2.5
