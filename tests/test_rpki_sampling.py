"""Unit tests for RPKI sampling in RIPEstatClient.check_rpki_status.

We patch the prefix list + per-prefix validation so the test never touches
the network. The goal is to pin three behaviours:

1. sample_size caps the number of validations performed.
2. The 'total_checked' key matches the sampled size.
3. Invalid prefixes land in the 'invalid' bucket so the security scorer
   can deduct points.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from route_sherlock.collectors.ripestat import RIPEstatClient
from route_sherlock.models.ripestat import RPKIValidation


def _fake_prefixes(n: int) -> SimpleNamespace:
    return SimpleNamespace(prefixes=[SimpleNamespace(prefix=f"192.0.{i}.0/24") for i in range(n)])


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


def test_sample_size_caps_validations(monkeypatch):
    client = RIPEstatClient()

    async def fake_prefixes(asn):
        return _fake_prefixes(100)

    calls = {"n": 0}

    async def fake_validation(prefix, asn):
        calls["n"] += 1
        return RPKIValidation(prefix=prefix, status="valid")

    monkeypatch.setattr(client, "get_announced_prefixes", fake_prefixes)
    monkeypatch.setattr(client, "get_rpki_validation", fake_validation)

    result = _run(client.check_rpki_status("AS64500", sample_size=8))
    assert calls["n"] == 8
    assert result["total_checked"] == 8
    assert len(result["valid"]) == 8


def test_invalid_prefixes_bucketed(monkeypatch):
    client = RIPEstatClient()

    async def fake_prefixes(asn):
        return _fake_prefixes(5)

    async def fake_validation(prefix, asn):
        # Mark prefix index 0 invalid, 1 not-found, rest valid.
        idx = int(prefix.split(".")[2])
        status = {0: "invalid", 1: "not-found"}.get(idx, "valid")
        return RPKIValidation(prefix=prefix, status=status)

    monkeypatch.setattr(client, "get_announced_prefixes", fake_prefixes)
    monkeypatch.setattr(client, "get_rpki_validation", fake_validation)

    result = _run(client.check_rpki_status("AS64500"))
    assert result["total_checked"] == 5
    assert len(result["invalid"]) == 1
    assert len(result["not_found"]) == 1
    assert len(result["valid"]) == 3


def test_no_sample_when_population_small(monkeypatch):
    client = RIPEstatClient()

    async def fake_prefixes(asn):
        return _fake_prefixes(3)

    async def fake_validation(prefix, asn):
        return RPKIValidation(prefix=prefix, status="valid")

    monkeypatch.setattr(client, "get_announced_prefixes", fake_prefixes)
    monkeypatch.setattr(client, "get_rpki_validation", fake_validation)

    result = _run(client.check_rpki_status("AS64500", sample_size=8))
    # 3 < 8, so all three are validated.
    assert result["total_checked"] == 3
    assert len(result["valid"]) == 3
