"""Peer Risk v2 — three-pillar scoring orchestrator.

Replaces the v1 single 0-90 composite score with three independently-classified
pillars: Track Record, Routing Hygiene, Coordination. Each pillar is
rule-scored (not weighted-sum) for auditability. Categorical output is
LOW / MEDIUM / HIGH / UNKNOWN. UNKNOWN is preferred to a false LOW on data
fetch failure — see spec section "Pillar scoring rules".
"""
from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import Any

from route_sherlock.collectors.bogons import check_bogons, BogonCheckResult
from route_sherlock.collectors.contacts import check_contacts, ContactCheckResult
from route_sherlock.collectors.irr import (
    ASSetStatus, IRRCoverageResult, check_as_set, get_irr_coverage,
)
from route_sherlock.collectors.peeringdb import PeeringDBClient
from route_sherlock.collectors.ripestat import RIPEstatClient
from route_sherlock.collectors.rpki import RPKIAuditResult, RPKIValidator
from route_sherlock.analysis.track_record import TrackRecordResult, check_track_record


PILLAR_CLASSES = ("LOW", "MEDIUM", "HIGH", "UNKNOWN")


@dataclass
class PillarScore:
    name: str
    points: int | None      # None = UNKNOWN
    classification: str     # LOW | MEDIUM | HIGH | UNKNOWN
    findings: list[str]     # human-readable evidence lines
    error: str | None = None


@dataclass
class ObservedFacts:
    network_name: str = ""
    network_type: str = ""               # from PeeringDB info_type (self-declared, displayed as such)
    transit_upstreams: int | None = None  # observed in RIS
    direct_downstreams: int | None = None  # observed in RIS (proxy for blast-radius; not full customer cone)


@dataclass
class Safeguards:
    """Concrete operational guidance derived from the pillar findings.

    Replaces the v1 binary SAFE/AVOID verdict with action-oriented advice
    aligned to the abstract's "practical safeguards" promise. The fields
    describe what the operator should do at session-up time.
    """
    posture: str               # PEER-STANDARD | PEER-WITH-SAFEGUARDS | PEER-CAUTIOUSLY | INVESTIGATE-FIRST | INSUFFICIENT-DATA
    posture_rationale: str
    filter_strategy: str       # ROA-permissive | strict-IRR | strict-IRR+ROA | hand-curated
    max_prefix_v4: int | None  # suggested hard cap; None = use upstream defaults
    max_prefix_v6: int | None
    preflight_steps: list[str] = field(default_factory=list)
    monitoring_steps: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class PeerRiskV2Result:
    asn: int
    network_name: str
    track_record: PillarScore
    routing_hygiene: PillarScore
    coordination: PillarScore
    observed: ObservedFacts
    safeguards: Safeguards    # graduated operational guidance (replaces binary verdict)
    data_sources: list[str]   # provenance — what we hit, when
    raw: dict[str, Any] = field(default_factory=dict)  # raw collector results for JSON output


# ----------------------------------------------------------------------------
# Scoring rules
# ----------------------------------------------------------------------------

def score_track_record(tr: TrackRecordResult) -> PillarScore:
    """Score Track Record with pattern detection.

    Rules:
    - Per-event weights by role + recency:
        injector_recent:   7pt each (within 24 mo)
        injector_older:    3pt each
        propagator_recent: 4pt each
        propagator_older:  1pt each
    - Pattern bonus for repeat offenders:
        2 fault events:    +3pt
        3+ fault events:   +5pt
    - Cap at 10. Classification: 0-2 LOW, 3-6 MEDIUM, 7+ HIGH.

    The pattern bonus is the key change from v1 — a single old incident
    decays to LOW, but multiple events across years compound into MEDIUM/HIGH
    because consistent past history is the strongest predictor of future risk.
    """
    findings: list[str] = []
    if tr.error:
        findings.append(f"GRIP query failed: {tr.error}")
        return PillarScore(name="Track Record", points=None, classification="UNKNOWN", findings=findings, error=tr.error)
    if not tr.matches:
        findings.append(
            f"No high-suspicion BGP anomalies involving AS{tr.asn} in GRIP "
            f"(coverage ~2019-present; total events seen: {tr.registry_size})"
        )
        return PillarScore(name="Track Record", points=0, classification="LOW", findings=findings)

    # "Recent" = within 24 months. Operators remember 2-year-old major incidents.
    from datetime import datetime, timezone
    today = datetime.now(timezone.utc)
    recent_y = today.year - 2
    recent_m = today.month
    cutoff = f"{recent_y:04d}-{recent_m:02d}"

    injector_recent = injector_older = 0
    propagator_recent = propagator_older = 0
    victim_count = 0

    for m in tr.matches:
        is_recent = m.date >= cutoff
        if m.role == "injector":
            if is_recent:
                injector_recent += 1
            else:
                injector_older += 1
            recency_tag = "RECENT" if is_recent else "historical"
            findings.append(
                f"{m.date}: documented as INJECTOR ({recency_tag}, severity={m.severity}) — "
                f"{m.summary[:80]}..."
            )
        elif m.role == "propagator":
            if is_recent:
                propagator_recent += 1
            else:
                propagator_older += 1
            recency_tag = "RECENT" if is_recent else "historical"
            findings.append(
                f"{m.date}: documented as propagator ({recency_tag}) — {m.summary[:80]}..."
            )
        elif m.role == "victim":
            victim_count += 1
            # Don't add per-victim lines individually — summarise at bottom
        elif m.role == "originator":
            propagator_older += 1
            findings.append(f"{m.date}: incident origin role — {m.summary[:80]}...")

    if victim_count:
        findings.append(f"appears as VICTIM in {victim_count} incident(s) (not a fault signal)")

    # Severity-weighted per-event scoring. Critical-severity events outrank
    # high-severity, which outrank medium. Recent events outrank historical.
    # Calibration note: older-high injector bumped 2→3 so a single famous
    # documented older incident lands MEDIUM (was LOW). Without this, networks
    # like AS21217 (Safe Host, 2019 leak) or AS37282 (MainOne, 2018 leak)
    # scored Track Record LOW despite the public post-mortem — counter-
    # intuitive on per-pillar reading.
    _WEIGHTS = {
        ("injector",   "recent",   "critical"): 9,
        ("injector",   "recent",   "high"):     7,
        ("injector",   "recent",   "medium"):   4,
        ("injector",   "older",    "critical"): 5,
        ("injector",   "older",    "high"):     3,
        ("injector",   "older",    "medium"):   1,
        ("propagator", "recent",   "critical"): 5,
        ("propagator", "recent",   "high"):     4,
        ("propagator", "recent",   "medium"):   2,
        ("propagator", "older",    "critical"): 2,
        ("propagator", "older",    "high"):     1,
        ("propagator", "older",    "medium"):   1,
    }
    points = 0
    for m in tr.matches:
        if m.role not in ("injector", "propagator"):
            continue
        recency = "recent" if m.date >= cutoff else "older"
        sev = m.severity if m.severity in ("critical", "high", "medium") else "high"
        points += _WEIGHTS.get((m.role, recency, sev), 1)

    # Pattern bonus — compounding for repeat offenders
    fault_events = injector_recent + injector_older + propagator_recent + propagator_older
    if fault_events >= 3:
        points += 5
        findings.append(
            f"⚠ Pattern detected: {fault_events} GRIP attacker-role clusters across coverage window → +5 pattern bonus"
        )
    elif fault_events == 2:
        points += 3
        findings.append(
            f"⚠ Two GRIP attacker-role clusters — emerging pattern → +3 pattern bonus"
        )

    points = min(points, 10)

    if points <= 2:
        cls = "LOW"
    elif points <= 6:
        cls = "MEDIUM"
    else:
        cls = "HIGH"
    return PillarScore(name="Track Record", points=points, classification=cls, findings=findings)


def score_routing_hygiene(
    rpki: RPKIAuditResult | None, bogon: BogonCheckResult | None,
    irr: IRRCoverageResult | None, as_set: ASSetStatus | None,
) -> PillarScore:
    """Score Routing Hygiene per spec composite rules."""
    findings: list[str] = []
    points = 0
    errors: list[str] = []

    # ROA coverage — thresholds calibrated against actual Tier-1 / transit
    # deployment levels in 2026. <60% is "severe filter gap"; 60-85% is
    # "mediocre but industry-typical for Tier-1 carriers"; 85%+ is "good".
    # Old thresholds (<80%=+4) false-positived large carriers like Verizon
    # that sit at ~78% — operationally that's average, not severe.
    if rpki is not None and rpki.total_prefixes > 0:
        cov = rpki.coverage_percent
        findings.append(
            f"ROA coverage: {cov:.1f}% ({rpki.valid:,} / {rpki.total_prefixes:,} prefixes valid, "
            f"VRP built {rpki.vrp_built_at})"
        )
        if cov < 60:
            points += 4
        elif cov < 85:
            points += 2

        # Ratio-based invalid penalty — 8/5455 = 0.15% should not score the
        # same as 50/100. Use percentage of total announced prefixes.
        if rpki.total_invalids > 0:
            invalid_pct = 100.0 * rpki.total_invalids / rpki.total_prefixes
            findings.append(
                f"ROA invalids: {rpki.total_invalids} ({invalid_pct:.2f}% of announced) "
                f"— asn-mismatch: {rpki.invalid_asn}, length-out-of-range: {rpki.invalid_length}"
            )
            if invalid_pct >= 5.0:
                points += 4
            elif invalid_pct >= 1.0:
                points += 2
            elif invalid_pct >= 0.5:
                points += 1
            # <0.5% (e.g., 8/5455) is informational only — likely transferred or transient
        else:
            findings.append("ROA invalids: 0")
    else:
        errors.append("RPKI audit unavailable")

    # AS-SET registration
    if as_set is not None:
        if as_set.exists_in_irr:
            mod = f" (modified {as_set.last_modified})" if as_set.last_modified else ""
            findings.append(f"AS-SET: {as_set.as_set_name}{mod}")
        elif as_set.error and "no AS-SET" in as_set.error:
            findings.append("AS-SET: not declared in PeeringDB")
            points += 2
        else:
            findings.append(f"AS-SET: declared as {as_set.as_set_name} but NOT FOUND in IRR")
            points += 2
    else:
        errors.append("AS-SET status unavailable")

    # IRR coverage
    if irr is not None and not irr.error:
        findings.append(
            f"IRR route-object coverage: {irr.coverage_percent:.1f}% "
            f"({irr.announced_prefixes:,} announced, {irr.registered_prefixes:,} in IRR)"
        )
        if irr.coverage_percent < 80:
            points += 1
    elif irr is not None and irr.error:
        errors.append(f"IRR coverage check failed: {irr.error}")

    # Bogons
    if bogon is not None:
        if bogon.has_bogons:
            findings.append(
                f"Bogon announcements: {len(bogon.matches)} found — "
                + ", ".join(f"{m.announced_prefix} ({m.reason})" for m in bogon.matches[:3])
            )
            points += 3
        else:
            findings.append("Bogons: none observed")
    else:
        errors.append("Bogon check unavailable")

    # If everything failed, return UNKNOWN
    if rpki is None and bogon is None and irr is None and as_set is None:
        return PillarScore(
            name="Routing Hygiene", points=None, classification="UNKNOWN",
            findings=[], error="; ".join(errors) or "All hygiene signals failed",
        )

    points = min(points, 10)
    if points <= 2:
        cls = "LOW"
    elif points <= 5:
        cls = "MEDIUM"
    else:
        cls = "HIGH"
    if errors:
        findings.append(f"⚠ partial data: {'; '.join(errors)}")
    return PillarScore(name="Routing Hygiene", points=points, classification=cls, findings=findings)


def score_coordination(contacts: ContactCheckResult | None) -> PillarScore:
    """Score Coordination per spec rules."""
    if contacts is None or contacts.error:
        err = (contacts.error if contacts else "no data") or "no data"
        return PillarScore(
            name="Coordination", points=None, classification="UNKNOWN",
            findings=[], error=err,
        )

    findings: list[str] = []
    points = 0

    if contacts.noc_email:
        findings.append(f"NOC contact: {contacts.noc_email}")
    else:
        findings.append("NOC contact: not published (PeeringDB Public)")
        points += 4
    if contacts.abuse_email:
        findings.append(f"Abuse contact: {contacts.abuse_email}")
    else:
        findings.append("Abuse contact: not published (PeeringDB Public)")
        points += 4
    # Technical and Policy are informational — flagged but not heavily scored,
    # since their absence with NOC+Abuse present is acceptable operational
    # practice. Penalising for missing tech/policy moved Cloudflare from LOW
    # to MEDIUM, which over-states risk.
    if contacts.has_technical:
        findings.append("Technical contact: present")
    else:
        findings.append("Technical contact: not published")
    if contacts.has_policy:
        findings.append("Policy contact: present")

    if not contacts.contacts:
        findings.append(
            "Note: PeeringDB POCs may be set to non-Public visibility — "
            "we can only score what's publicly observable. Operationally, "
            "non-public contacts add friction during incidents."
        )

    points = min(points, 10)
    if points == 0:
        cls = "LOW"
    elif points <= 3:
        cls = "MEDIUM"
    else:
        cls = "HIGH"
    return PillarScore(name="Coordination", points=points, classification=cls, findings=findings)


def derive_safeguards(
    tr: PillarScore, rh: PillarScore, co: PillarScore,
    observed: ObservedFacts, raw_pdb_prefixes_v4: int | None = None,
    raw_pdb_prefixes_v6: int | None = None,
) -> Safeguards:
    """Build operational safeguards proportional to the measured risk.

    Replaces the binary AVOID/SAFE verdict. The output describes what to do
    at session turn-up: filter strategy, max-prefix caps, pre-flight steps,
    ongoing monitoring. This matches what experienced peering coordinators
    actually produce after evaluating a candidate.
    """
    unknown_count = sum(1 for p in (tr, rh, co) if p.classification == "UNKNOWN")
    if unknown_count >= 2:
        return Safeguards(
            posture="INSUFFICIENT-DATA",
            posture_rationale="Two or more pillars returned UNKNOWN; cannot recommend safeguards on partial data.",
            filter_strategy="(re-run when data sources are reachable)",
            max_prefix_v4=None, max_prefix_v6=None,
        )

    # Decide posture
    if tr.classification == "HIGH":
        posture = "INVESTIGATE-FIRST"
        rationale = (
            "Track Record HIGH — documented past incidents are the strongest predictor of "
            "future risk. Manually review the cited incidents before turning up a session."
        )
    elif tr.classification == "MEDIUM" and rh.classification == "HIGH":
        posture = "PEER-CAUTIOUSLY"
        rationale = "Documented past faults combined with currently weak routing hygiene."
    elif rh.classification == "HIGH":
        posture = "PEER-WITH-SAFEGUARDS"
        rationale = "Routing Hygiene HIGH — strict filtering required."
    elif tr.classification == "HIGH" or rh.classification == "MEDIUM" or co.classification == "HIGH":
        posture = "PEER-WITH-SAFEGUARDS"
        rationale = "At least one pillar above LOW — apply standard tier-2 safeguards."
    elif rh.classification == "MEDIUM" or co.classification == "MEDIUM":
        posture = "PEER-WITH-SAFEGUARDS"
        rationale = "Mid-classification on hygiene or coordination — standard safeguards."
    else:
        posture = "PEER-STANDARD"
        rationale = "All measured pillars LOW — standard prefix filter sufficient."

    # Filter strategy depends on what's available
    if rh.classification in ("LOW",) and tr.classification == "LOW":
        filter_strategy = "ROA-permissive (accept ROA-valid + AS-SET prefix-list)"
    elif rh.classification == "HIGH":
        filter_strategy = "strict-IRR (accept only IRR-listed prefixes that ROA-validate)"
    elif tr.classification in ("MEDIUM", "HIGH"):
        filter_strategy = "strict-IRR+ROA (full validation both ways; reject NOT-FOUND in high-incident region)"
    else:
        filter_strategy = "standard-IRR+ROA (accept IRR-listed + ROA-valid or ROA NOT-FOUND)"

    # Max-prefix caps: derive from PeeringDB declared + safety margin
    cap_v4 = cap_v6 = None
    if raw_pdb_prefixes_v4 is not None and raw_pdb_prefixes_v4 > 0:
        # Soft cap = declared, hard cap = declared * 1.3 (Tier-1) or 1.5 (others)
        multiplier = 1.3 if (observed.transit_upstreams or 0) > 30 else 1.5
        cap_v4 = int(raw_pdb_prefixes_v4 * multiplier)
    if raw_pdb_prefixes_v6 is not None and raw_pdb_prefixes_v6 > 0:
        cap_v6 = int(raw_pdb_prefixes_v6 * (1.5 if (observed.transit_upstreams or 0) <= 30 else 1.3))

    # Pre-flight steps
    preflight: list[str] = []
    if co.classification == "HIGH":
        preflight.append(
            "Establish out-of-band NOC + abuse contact before session-up — "
            "PeeringDB POCs are not publicly visible"
        )
    if rh.classification in ("MEDIUM", "HIGH"):
        # Specific hygiene-driven preflight
        for f in rh.findings:
            if "AS-SET" in f and ("not declared" in f or "NOT FOUND" in f or "not resolvable" in f):
                preflight.append(
                    "Confirm AS-SET name with operator directly — "
                    "PeeringDB irr_as_set is empty and canonical fallbacks did not resolve"
                )
                break
        if any("ROA coverage" in f and "%" in f for f in rh.findings):
            # Find the ROA line
            for f in rh.findings:
                if "ROA coverage" in f and "%" in f:
                    # Parse coverage percent
                    try:
                        pct = float(f.split("%")[0].split()[-1])
                        if pct < 95:
                            preflight.append(
                                f"Plan for ROA-not-found prefixes (coverage at {pct:.1f}%) — "
                                "decide accept-or-drop policy per your RPKI posture"
                            )
                    except (ValueError, IndexError):
                        pass
                    break
    if tr.classification == "HIGH":
        preflight.append(
            "Manually review cited past incidents in Track Record — confirm the operator has "
            "implemented filter improvements since"
        )
        preflight.append(
            "Consider a maintenance-window session bring-up with capped max-prefix initially"
        )

    # Monitoring
    monitoring = [
        "Alert on max-prefix utilisation crossing 80% of hard cap",
        "Monthly: re-run peer-risk; flag if Track Record adds new entries or ROA coverage drops",
    ]
    if tr.classification in ("MEDIUM", "HIGH"):
        monitoring.insert(0,
            "Subscribe to BGP-alert feed for this ASN (BGPalerter, Cloudflare Radar) — "
            "elevated history justifies tighter monitoring"
        )
    if rh.classification == "HIGH":
        monitoring.insert(0,
            "Weekly: review prefix-filter generation logs; flag if AS-SET expansion grows >10% week-over-week"
        )

    notes: list[str] = []
    if observed.transit_upstreams is not None and observed.transit_upstreams > 30:
        notes.append(
            f"Backbone-class network ({observed.transit_upstreams} upstreams, "
            f"{observed.direct_downstreams} downstreams) — context for safeguard severity"
        )

    return Safeguards(
        posture=posture, posture_rationale=rationale,
        filter_strategy=filter_strategy,
        max_prefix_v4=cap_v4, max_prefix_v6=cap_v6,
        preflight_steps=preflight, monitoring_steps=monitoring, notes=notes,
    )


# ----------------------------------------------------------------------------
# Orchestrator
# ----------------------------------------------------------------------------

async def evaluate_peer_risk_v2(asn: int, history_months: int = 60) -> PeerRiskV2Result:
    """Run all v2 collectors and produce a three-pillar risk profile."""
    data_sources: list[str] = []

    # PeeringDB lookup for network metadata + AS-SET name
    pdb_network = None
    pdb_error = None
    try:
        async with PeeringDBClient(api_key=os.environ.get("PEERINGDB_API_KEY")) as pdb:
            pdb_network = await pdb.get_network_by_asn(asn)
            data_sources.append("PeeringDB (network profile)")
    except Exception as e:
        pdb_error = str(e)

    network_name = pdb_network.name if pdb_network else f"AS{asn}"
    network_type = pdb_network.info_type if pdb_network else ""
    as_set_name = pdb_network.irr_as_set if pdb_network else None

    # RIPEstat — announced prefixes (needed for RPKI/bogon/IRR) + neighbours
    announced_prefixes: list[str] = []
    transit_upstreams: int | None = None
    direct_downstreams: int | None = None
    ripestat_error = None
    try:
        async with RIPEstatClient() as ripe:
            ap = await ripe.get_announced_prefixes(f"AS{asn}")
            announced_prefixes = [p.prefix for p in ap.prefixes if p.prefix]
            data_sources.append(f"RIPEstat announced-prefixes ({len(announced_prefixes)} prefixes)")
            try:
                neigh = await ripe.get_as_neighbours(str(asn))
                # neighbour_counts is the canonical signal from RIPEstat
                counts = neigh.neighbour_counts or {}
                transit_upstreams = counts.get("left") or len(neigh.left) or len(neigh.upstreams)
                direct_downstreams = counts.get("right") or len(neigh.right) or len(neigh.downstreams)
                data_sources.append("RIPEstat asn-neighbours")
            except Exception:
                pass
    except Exception as e:
        ripestat_error = str(e)

    # Run independent collectors concurrently
    rpki_task = _run_rpki(announced_prefixes, asn) if announced_prefixes else _noop()
    irr_task = get_irr_coverage(asn, announced_prefixes) if announced_prefixes else _noop()
    as_set_task = check_as_set(asn, as_set_name, network_name=network_name)
    contacts_task = check_contacts(asn)
    bogon_result = check_bogons(announced_prefixes, asn) if announced_prefixes else None
    track_record_task = check_track_record(asn, window_months=history_months)

    rpki_result, irr_result, as_set_result, contacts_result, track_record = await asyncio.gather(
        rpki_task, irr_task, as_set_task, contacts_task, track_record_task,
        return_exceptions=True,
    )
    if isinstance(track_record, Exception):
        from route_sherlock.analysis.track_record import TrackRecordResult as _TR
        track_record = _TR(asn=asn, window_months=history_months, error=str(track_record))
    # Replace exceptions with None and record errors
    if isinstance(rpki_result, Exception):
        rpki_result = None
    if isinstance(irr_result, Exception):
        irr_result = None
    if isinstance(as_set_result, Exception):
        as_set_result = None
    if isinstance(contacts_result, Exception):
        contacts_result = None
    if rpki_result is not None and announced_prefixes:
        data_sources.append(f"RPKI VRP set (Cloudflare rpki.json, audited {len(announced_prefixes)} prefixes)")
    if irr_result is not None:
        data_sources.append("IRR via whois.radb.net")
    if contacts_result is not None and not contacts_result.error:
        data_sources.append("PeeringDB POCs")
    if track_record.error:
        data_sources.append(f"GRIP API (error: {track_record.error[:60]})")
    else:
        injector_n = sum(1 for m in track_record.matches if m.role == "injector")
        data_sources.append(
            f"GRIP API ({track_record.registry_size} total events, "
            f"{injector_n} clustered attacker-role)"
        )

    # Score
    tr = score_track_record(track_record)
    rh = score_routing_hygiene(rpki_result, bogon_result, irr_result, as_set_result)
    co = score_coordination(contacts_result)

    observed = ObservedFacts(
        network_name=network_name,
        network_type=network_type or "unclassified",
        transit_upstreams=transit_upstreams,
        direct_downstreams=direct_downstreams,
    )
    pdb_v4 = pdb_network.info_prefixes4 if pdb_network else None
    pdb_v6 = pdb_network.info_prefixes6 if pdb_network else None
    safeguards = derive_safeguards(tr, rh, co, observed,
                                   raw_pdb_prefixes_v4=pdb_v4,
                                   raw_pdb_prefixes_v6=pdb_v6)

    return PeerRiskV2Result(
        asn=asn, network_name=network_name,
        track_record=tr, routing_hygiene=rh, coordination=co,
        observed=observed,
        safeguards=safeguards,
        data_sources=data_sources,
        raw={
            "track_record": _as_dict(track_record),
            "rpki": _as_dict(rpki_result),
            "irr": _as_dict(irr_result),
            "as_set": _as_dict(as_set_result),
            "bogon": _as_dict(bogon_result),
            "contacts": _as_dict(contacts_result),
            "peeringdb_error": pdb_error,
            "ripestat_error": ripestat_error,
        },
    )


async def _noop():
    return None


async def _run_rpki(prefixes: list[str], asn: int) -> RPKIAuditResult | None:
    try:
        async with RPKIValidator() as v:
            return v.audit(prefixes, origin_asn=asn)
    except Exception:
        return None


def _as_dict(obj):
    if obj is None:
        return None
    if hasattr(obj, "__dataclass_fields__"):
        from dataclasses import asdict
        return asdict(obj)
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    return obj
