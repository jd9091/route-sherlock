"""
Smoke tests for route_sherlock.analysis.safeguards.compute_safeguards.

These tests pin the safeguard-generation logic to the four risk tiers
(LOW / MODERATE / ELEVATED / HIGH) described in the project README and
in the "Practical Safeguards by Risk Level" reference table. No network.
"""
from __future__ import annotations

import pytest

from route_sherlock.analysis.safeguards import compute_safeguards


def _risk_data(
    risk_level: str,
    *,
    total_score: int,
    asn: int = 64500,
    name: str = "TEST-NET",
    irr_as_set: str | None = "RADB::AS-TEST",
    prefix_count: int | None = 10,
) -> dict:
    return {
        "target_asn": asn,
        "total_score": total_score,
        "max_score": 100,
        "risk_level": risk_level,
        "network": {
            "name": name,
            **({"irr_as_set": irr_as_set} if irr_as_set else {}),
        },
        "stability": {"prefix_count": prefix_count} if prefix_count is not None else {},
    }


def test_low_risk_uses_2x_multiplier_and_warn_invalid():
    sg = compute_safeguards(_risk_data("LOW", total_score=95, prefix_count=10))
    assert sg["risk_level"] == "LOW"
    assert sg["decline"] is False
    assert sg["max_prefix"] == 20
    assert "2× announced (10)" in sg["max_prefix_basis"]
    assert sg["irr_strictness"] == "standard"
    assert sg["rpki_policy"] == "warn-invalid"
    assert sg["warnings"] == []


def test_moderate_risk_uses_1_5x_multiplier_and_reject_invalid():
    sg = compute_safeguards(_risk_data("MODERATE", total_score=72, prefix_count=7))
    assert sg["risk_level"] == "MODERATE"
    assert sg["decline"] is False
    assert sg["max_prefix"] == 11  # ceil(7 * 1.5) = 11
    assert sg["irr_strictness"] == "strict"
    assert sg["rpki_policy"] == "reject-invalid"
    assert sg["monitoring"] == "recommended"


def test_elevated_risk_uses_1_2x_multiplier_and_strict_plus_verify():
    sg = compute_safeguards(_risk_data("ELEVATED", total_score=50, prefix_count=100))
    assert sg["max_prefix"] == 120  # ceil(100 * 1.2)
    assert sg["irr_strictness"] == "strict + verify"
    assert sg["rpki_policy"] == "reject-invalid"
    assert sg["monitoring"] == "required"


def test_high_risk_declines_with_no_safeguard_values():
    sg = compute_safeguards(_risk_data("HIGH", total_score=20))
    assert sg["decline"] is True
    assert sg["max_prefix"] is None
    assert sg["irr_filter"] is None
    assert sg["rpki_policy"] is None
    assert "decline" in sg["recommendation"].lower()


def test_max_prefix_has_minimum_floor_of_5():
    # A peer announcing just 1 prefix should still get a sane non-trivial cap.
    sg = compute_safeguards(_risk_data("LOW", total_score=85, prefix_count=1))
    assert sg["max_prefix"] == 5


def test_missing_irr_as_set_emits_warning_not_error():
    sg = compute_safeguards(_risk_data("MODERATE", total_score=70, irr_as_set=None))
    assert sg["irr_filter"] is None
    assert any("IRR as-set" in w for w in sg["warnings"])
    # Still produces a usable max-prefix recommendation.
    assert sg["max_prefix"] is not None


def test_missing_prefix_count_falls_back_to_peeringdb_v4():
    data = _risk_data("MODERATE", total_score=70, prefix_count=None)
    data["network"]["prefixes_v4"] = 12
    sg = compute_safeguards(data)
    assert sg["max_prefix"] == 18  # ceil(12 * 1.5)
    assert "12" in sg["max_prefix_basis"]


def test_missing_prefix_count_with_no_fallback_emits_warning():
    data = _risk_data("MODERATE", total_score=70, prefix_count=None)
    sg = compute_safeguards(data)
    assert sg["max_prefix"] is None
    assert any("Announced-prefix count unavailable" in w for w in sg["warnings"])


def test_missing_risk_level_raises_value_error():
    with pytest.raises(ValueError, match="risk_level"):
        compute_safeguards({"target_asn": 64500, "network": {}})


def test_invalid_risk_level_raises_value_error():
    with pytest.raises(ValueError, match="risk_level"):
        compute_safeguards({"risk_level": "CRITICAL", "target_asn": 64500})


def test_rationale_includes_score_and_tier():
    sg = compute_safeguards(_risk_data("MODERATE", total_score=72, prefix_count=7))
    rationale_blob = " ".join(sg["rationale"])
    assert "72/100" in rationale_blob
    assert "MODERATE" in rationale_blob
