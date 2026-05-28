"""Track Record pillar — live BGP anomaly history from GRIP.

Sole signal source: Georgia Tech's GRIP API
(`https://api.grip.inetintel.cc.gatech.edu/dev/json/events`), filtered by
`min_susp >= 80` for high-confidence anomalies. Coverage extends from
~January 2019 to present.

Honest scope: GRIP captures algorithmically-detected anomalies. It does
NOT contain pre-2019 incidents. It does NOT predict first-time novel
leaks (no anomaly visible until it propagates). It does NOT separate
legitimate operational events (anycast, multi-homing) from genuine
hijacks with perfect accuracy. Operators should treat Track Record
findings as one input among three, not as a final verdict.

Output dataclasses preserve the historical shape (`TrackRecordResult`,
`IncidentMatch`) so downstream renderer + JSON output + scorer keep
working. Each GRIP attacker-role event becomes an injector
IncidentMatch; victim-role events become victim matches.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from route_sherlock.collectors.grip import (
    GripEvent, fetch_grip_events,
)


@dataclass
class IncidentMatch:
    incident_id: str
    date: str
    summary: str
    role: str            # injector | victim
    severity: str        # always "high" (filtered by min_susp>=80)
    reference: str       # GRIP UI URL
    duration_hours: float | None = None


@dataclass
class TrackRecordResult:
    asn: int
    window_months: int           # informational; GRIP coverage is fixed at ~2019-present
    matches: list[IncidentMatch] = field(default_factory=list)
    registry_last_updated: str = ""   # repurposed: GRIP fetch timestamp
    registry_size: int = 0            # repurposed: GRIP total event count for this ASN
    error: str | None = None

    @property
    def has_any_incidents(self) -> bool:
        return len(self.matches) > 0

    @property
    def as_injector_count(self) -> int:
        return sum(1 for m in self.matches if m.role == "injector")

    @property
    def as_propagator_count(self) -> int:
        return 0   # GRIP doesn't distinguish propagator from injector

    @property
    def recent_critical_count(self) -> int:
        cutoff = datetime.now(timezone.utc)
        cutoff_year = cutoff.year - 1
        cutoff_str = f"{cutoff_year}-{cutoff.month:02d}"
        return sum(1 for m in self.matches if m.role == "injector" and m.date >= cutoff_str)


def _cluster_attacker_events(events: list[GripEvent], asn: int) -> list[GripEvent]:
    """Collapse repeated GRIP attacker-role events on (victim_asn, month).

    GRIP often emits dozens of events for one operational incident. We pick
    the most recent event per (first_victim, year-month) pair as the
    representative so the pattern bonus reflects distinct incidents.
    """
    clusters: dict[tuple[str, str], GripEvent] = {}
    for e in events:
        if not e.involves_as_attacker(asn):
            continue
        victim_key = e.victims[0] if e.victims else "unknown"
        cluster_key = (victim_key, e.ymd_month)
        existing = clusters.get(cluster_key)
        if existing is None or e.view_ts > existing.view_ts:
            clusters[cluster_key] = e
    return list(clusters.values())


def _event_to_match(event: GripEvent, asn: int, role: str) -> IncidentMatch:
    pfx_summary = ", ".join(event.prefixes[:2])
    if len(event.prefixes) > 2:
        pfx_summary += f", +{len(event.prefixes) - 2} more"
    if role == "injector":
        other = ", ".join(event.victims[:2]) if event.victims else "?"
        summary = (
            f"GRIP {event.event_type} event — AS{asn} announced as origin alongside "
            f"AS{other} for {pfx_summary}"
        )
    else:
        other = ", ".join(event.attackers[:2]) if event.attackers else "?"
        summary = (
            f"GRIP {event.event_type} event — AS{asn}'s prefix(es) {pfx_summary} "
            f"appeared with AS{other}"
        )
    grip_url = f"https://grip.inetintel.cc.gatech.edu/v1/event/{event.event_type}/{event.event_id}"
    return IncidentMatch(
        incident_id=event.event_id,
        date=event.date,
        summary=summary,
        role=role,
        severity="high",
        reference=grip_url,
    )


async def check_track_record(asn: int, window_months: int = 60) -> TrackRecordResult:
    """Query GRIP for high-suspicion events involving the target ASN.

    Args:
        asn: Target ASN.
        window_months: Informational only — GRIP coverage starts ~Jan 2019;
            we let the algorithm decide what's significant.

    Returns:
        TrackRecordResult. If GRIP fails, `error` is set; scorer classifies UNKNOWN.
    """
    grip = await fetch_grip_events(asn)

    if grip.error:
        return TrackRecordResult(
            asn=asn, window_months=window_months,
            registry_last_updated=grip.fetched_at,
            registry_size=0, error=grip.error,
        )

    matches: list[IncidentMatch] = []
    for event in sorted(_cluster_attacker_events(grip.events, asn), key=lambda e: -e.view_ts):
        matches.append(_event_to_match(event, asn, role="injector"))
    for ev in [e for e in grip.events if e.involves_as_victim(asn)][:5]:
        matches.append(_event_to_match(ev, asn, role="victim"))

    return TrackRecordResult(
        asn=asn,
        window_months=window_months,
        matches=matches,
        registry_last_updated=grip.fetched_at,
        registry_size=grip.total_records,
    )
