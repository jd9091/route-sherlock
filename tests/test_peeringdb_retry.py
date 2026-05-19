"""Unit tests for the PeeringDB retry/backoff helper."""
from __future__ import annotations

from route_sherlock.collectors.peeringdb import PeeringDBClient


def test_retry_delay_uses_retry_after_header():
    d = PeeringDBClient._retry_delay(attempt=0, retry_after="7")
    # Retry-After honored; jitter adds 0–0.5s.
    assert 7.0 <= d <= 7.5


def test_retry_delay_falls_back_to_exponential():
    d0 = PeeringDBClient._retry_delay(attempt=0)
    d2 = PeeringDBClient._retry_delay(attempt=2)
    # 2^0=1 plus jitter; 2^2=4 plus jitter. Strictly monotonic across attempts.
    assert 1.0 <= d0 <= 1.5
    assert 4.0 <= d2 <= 4.5


def test_retry_delay_is_capped_at_30_seconds():
    # 2^10 would be 1024s without the cap.
    d = PeeringDBClient._retry_delay(attempt=10)
    assert 30.0 <= d <= 30.5


def test_retry_delay_ignores_garbage_retry_after():
    d = PeeringDBClient._retry_delay(attempt=1, retry_after="soon")
    # Falls back to exponential: 2^1 = 2.
    assert 2.0 <= d <= 2.5
