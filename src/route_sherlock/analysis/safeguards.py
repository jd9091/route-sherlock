"""
Peer safeguard generation.

Maps a peer-risk assessment to concrete BGP safeguards (max-prefix limit,
IRR filter target, RPKI policy) per the risk-tier table described in the
project's "Practical Safeguards by Risk Level" reference:

    LOW       2x announced    Standard IRR        Warn on RPKI-invalid
    MODERATE  1.5x announced  Strict IRR          Reject RPKI-invalid
    ELEVATED  1.2x announced  Strict + verify     Reject RPKI-invalid
    HIGH      Decline         N/A                  N/A

The function is pure: it consumes the `risk_data` dict that
``run_peer_risk`` builds and emits a `SafeguardsResult` dict for display.
"""
from __future__ import annotations

from math import ceil
from typing import Any


_TIER: dict[str, dict[str, Any]] = {
    "LOW": {
        "multiplier": 2.0,
        "irr_strictness": "standard",
        "rpki_policy": "warn-invalid",
        "monitoring": "standard",
        "recommendation": "Recommended — standard peering process",
    },
    "MODERATE": {
        "multiplier": 1.5,
        "irr_strictness": "strict",
        "rpki_policy": "reject-invalid",
        "monitoring": "recommended",
        "recommendation": "Acceptable — implement monitoring",
    },
    "ELEVATED": {
        "multiplier": 1.2,
        "irr_strictness": "strict + verify",
        "rpki_policy": "reject-invalid",
        "monitoring": "required",
        "recommendation": "Caution — strict prefix limits, IRR filtering",
    },
    "HIGH": {
        "multiplier": None,
        "irr_strictness": None,
        "rpki_policy": None,
        "monitoring": None,
        "recommendation": "Not recommended — decline or require remediation",
    },
}


def _announced_count(risk_data: dict[str, Any]) -> int | None:
    """Best-effort announced-prefix count.

    Prefers BGP-observed (RIPEstat stability.prefix_count) over self-reported
    PeeringDB info_prefixes4, since the BGP-observed value matches what a
    candidate peer actually advertises.
    """
    stab = risk_data.get("stability") or {}
    if isinstance(stab.get("prefix_count"), int):
        return stab["prefix_count"]
    net = risk_data.get("network") or {}
    v4 = net.get("prefixes_v4")
    if isinstance(v4, int) and v4 > 0:
        return v4
    return None


def compute_safeguards(risk_data: dict[str, Any]) -> dict[str, Any]:
    """Generate per-risk-tier safeguards for a candidate peer.

    `risk_data` is the dict assembled by ``run_peer_risk``; the only required
    field is ``risk_level``. Missing optional fields are reported as warnings
    rather than raising.
    """
    risk_level = risk_data.get("risk_level")
    if risk_level not in _TIER:
        raise ValueError(
            f"risk_data['risk_level'] missing or invalid (got {risk_level!r}); "
            "run the peer-risk pipeline first."
        )

    tier = _TIER[risk_level]
    network = risk_data.get("network") or {}
    asn = risk_data.get("target_asn")
    warnings: list[str] = []

    out: dict[str, Any] = {
        "asn": asn,
        "network_name": network.get("name"),
        "risk_level": risk_level,
        "total_score": risk_data.get("total_score"),
        "max_score": risk_data.get("max_score"),
        "recommendation": tier["recommendation"],
        "rationale": [],
        "warnings": warnings,
    }

    if risk_level == "HIGH":
        out.update({
            "decline": True,
            "max_prefix": None,
            "max_prefix_basis": None,
            "irr_filter": None,
            "irr_strictness": None,
            "rpki_policy": None,
            "monitoring": None,
        })
        out["rationale"].append(
            f"Score {out['total_score']}/{out['max_score']} (HIGH) — "
            "decline session or require remediation before peering."
        )
        return out

    announced = _announced_count(risk_data)
    multiplier: float = tier["multiplier"]

    if announced is None:
        max_prefix = None
        max_prefix_basis = "announced count unavailable"
        warnings.append(
            "Announced-prefix count unavailable — verify via the peer's "
            "BGP advertisements before setting maximum-prefix."
        )
    else:
        max_prefix = max(ceil(announced * multiplier), 5)
        max_prefix_basis = f"{multiplier:g}× announced ({announced})"

    irr_as_set = network.get("irr_as_set")
    if not irr_as_set:
        warnings.append(
            "No IRR as-set registered in PeeringDB — request one from the "
            "peer, or use an explicit prefix-list per RFC 7948."
        )

    out.update({
        "decline": False,
        "max_prefix": max_prefix,
        "max_prefix_basis": max_prefix_basis,
        "irr_filter": irr_as_set,
        "irr_strictness": tier["irr_strictness"],
        "rpki_policy": tier["rpki_policy"],
        "monitoring": tier["monitoring"],
    })

    out["rationale"].append(
        f"Score {out['total_score']}/{out['max_score']} ({risk_level}) — "
        f"apply {risk_level}-tier safeguards."
    )
    if max_prefix is not None:
        out["rationale"].append(
            f"Cap maximum-prefix at {max_prefix} ({max_prefix_basis})."
        )
    out["rationale"].append(
        f"Apply {tier['irr_strictness']} IRR filtering; {tier['rpki_policy']}."
    )

    return out
