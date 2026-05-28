"""GRIP — Global Routing Intelligence Platform collector.

Replaces the bundled `known_incidents.json` registry with live per-ASN queries
against Georgia Tech's GRIP API. GRIP runs continuous anomaly detection on
RIPE RIS / RouteViews streams and labels each event with `attackers` and
`victims` lists — algorithmic, not hand-curated.

Coverage: ~January 2019 to present. Pre-2019 famous incidents (e.g. the 2010
China Telecom 37k-prefix leak) are out of scope. That trade is intentional —
we'd rather have continuous live coverage than a frozen curated list.

API shape (probed 2026-05-26):

    GET https://api.grip.inetintel.cc.gatech.edu/dev/json/events
        ?asns=N
        &min_susp=N        # suspicion score floor (0–100); 80 is "high-confidence"
        &length=N          # page size (max 10000)
        &start=N           # pagination offset
    -> { copyright, data: [event, ...], recordsTotal, recordsFiltered }

Each event has:
    event_type:   "moas" | "submoas" | "edges" | ...
    id:           "<type>-<view_ts>-<asnX>=<asnY>"
    view_ts:      unix epoch
    summary:      { ases, attackers, victims, prefixes, tags, ... }
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import httpx

GRIP_API = "https://api.grip.inetintel.cc.gatech.edu/dev/json/events"
CACHE_DIR = Path.home() / ".cache" / "route-sherlock" / "grip"
DEFAULT_CACHE_TTL = 6 * 3600        # 6h — events backfill; refresh a few times daily
DEFAULT_MIN_SUSPICION = 80          # only count high-confidence events
DEFAULT_PAGE_SIZE = 100
MAX_EVENTS = 500                    # safety cap; AS4134 returns ~1100 raw events


@dataclass
class GripEvent:
    """One GRIP-detected BGP anomaly event."""
    event_id: str
    event_type: str             # moas | submoas | edges | ...
    view_ts: int                # unix epoch (UTC)
    attackers: list[str]        # ASN strings; algorithmic inference
    victims: list[str]
    prefixes: list[str]
    tags: list[str] = field(default_factory=list)

    @property
    def date(self) -> str:
        return datetime.fromtimestamp(self.view_ts, timezone.utc).date().isoformat()

    @property
    def ymd_month(self) -> str:
        return datetime.fromtimestamp(self.view_ts, timezone.utc).strftime("%Y-%m")

    def involves_as_attacker(self, asn: int) -> bool:
        return str(asn) in self.attackers

    def involves_as_victim(self, asn: int) -> bool:
        return str(asn) in self.victims


@dataclass
class GripQueryResult:
    """Result of querying GRIP for events involving a target ASN."""
    asn: int
    min_suspicion: int
    events: list[GripEvent]
    total_records: int          # GRIP's reported total (may exceed events list)
    fetched_at: str             # ISO timestamp of the fetch
    error: str | None = None

    @property
    def as_attacker(self) -> list[GripEvent]:
        return [e for e in self.events if e.involves_as_attacker(self.asn)]

    @property
    def as_victim(self) -> list[GripEvent]:
        return [e for e in self.events if e.involves_as_victim(self.asn)]


class GripError(Exception):
    pass


def _cache_path(asn: int, min_suspicion: int) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"as{asn}_susp{min_suspicion}.json"


def _try_cached(asn: int, min_suspicion: int, ttl: int) -> GripQueryResult | None:
    cache = _cache_path(asn, min_suspicion)
    if not cache.exists():
        return None
    if time.time() - cache.stat().st_mtime > ttl:
        return None
    try:
        data = json.loads(cache.read_text())
    except json.JSONDecodeError:
        return None
    events = [
        GripEvent(
            event_id=e["event_id"], event_type=e["event_type"],
            view_ts=e["view_ts"], attackers=e["attackers"],
            victims=e["victims"], prefixes=e["prefixes"],
            tags=e.get("tags", []),
        )
        for e in data["events"]
    ]
    return GripQueryResult(
        asn=data["asn"], min_suspicion=data["min_suspicion"],
        events=events, total_records=data["total_records"],
        fetched_at=data["fetched_at"], error=data.get("error"),
    )


def _write_cache(result: GripQueryResult) -> None:
    payload = {
        "asn": result.asn,
        "min_suspicion": result.min_suspicion,
        "fetched_at": result.fetched_at,
        "total_records": result.total_records,
        "error": result.error,
        "events": [
            {
                "event_id": e.event_id,
                "event_type": e.event_type,
                "view_ts": e.view_ts,
                "attackers": e.attackers,
                "victims": e.victims,
                "prefixes": e.prefixes,
                "tags": e.tags,
            }
            for e in result.events
        ],
    }
    _cache_path(result.asn, result.min_suspicion).write_text(json.dumps(payload))


async def fetch_grip_events(
    asn: int,
    min_suspicion: int = DEFAULT_MIN_SUSPICION,
    page_size: int = DEFAULT_PAGE_SIZE,
    max_events: int = MAX_EVENTS,
    cache_ttl: int = DEFAULT_CACHE_TTL,
    timeout: float = 30.0,
) -> GripQueryResult:
    """Fetch high-suspicion GRIP events involving the target ASN.

    GRIP returns events where the ASN appears in EITHER attackers OR victims.
    The caller decides which role to weight. We cap at max_events to keep
    cold-cache fetches reasonable for prolific networks (AS4134 has ~1100
    raw events; min_susp=80 reduces this to ~34).

    Returns a GripQueryResult even on API failure — `error` will be set and
    `events` will be empty. The pillar scorer treats that as UNKNOWN.
    """
    cached = _try_cached(asn, min_suspicion, cache_ttl)
    if cached is not None:
        return cached

    fetched_at = datetime.now(timezone.utc).isoformat()
    params_base = {"asns": str(asn), "min_susp": str(min_suspicion), "length": str(page_size)}

    events: list[GripEvent] = []
    total_records = 0
    error: str | None = None
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            start = 0
            while True:
                params = {**params_base, "start": str(start)}
                r = await client.get(GRIP_API, params=params)
                r.raise_for_status()
                payload = r.json()
                total_records = payload.get("recordsTotal", 0)
                batch = payload.get("data", [])
                if not batch:
                    break
                for ev in batch:
                    summary = ev.get("summary", {}) or {}
                    events.append(GripEvent(
                        event_id=ev.get("id", ""),
                        event_type=ev.get("event_type", "unknown"),
                        view_ts=int(ev.get("view_ts", 0)),
                        attackers=[str(a) for a in summary.get("attackers", []) or []],
                        victims=[str(v) for v in summary.get("victims", []) or []],
                        prefixes=list(summary.get("prefixes", []) or []),
                        tags=[t.get("name", "") for t in summary.get("tags", []) or [] if isinstance(t, dict)],
                    ))
                if len(events) >= max_events or len(batch) < page_size:
                    break
                start += page_size
    except httpx.HTTPError as e:
        error = f"GRIP API error: {e}"
    except (KeyError, ValueError, json.JSONDecodeError) as e:
        error = f"GRIP API response parse error: {e}"

    result = GripQueryResult(
        asn=asn, min_suspicion=min_suspicion,
        events=events, total_records=total_records,
        fetched_at=fetched_at, error=error,
    )
    if error is None and events:
        _write_cache(result)
    return result
