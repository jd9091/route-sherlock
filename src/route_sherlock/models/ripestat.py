"""
RIPEstat API Models.

Pydantic models for RIPEstat Data API responses.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class RIPEstatResponse(BaseModel):
    """Wrapper for RIPEstat API responses."""
    status: str = ""
    server_id: str = ""
    status_code: int = 200
    version: str = ""
    cached: bool = False
    data_call_status: str = ""
    data_call_name: str = ""
    query_id: str = ""
    process_time: int = 0
    build_version: str = ""
    time: str = ""
    data: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        return self.status == "ok" or self.status_code == 200


class ASOverview(BaseModel):
    """AS overview information."""
    resource: str = ""
    holder: str | None = None
    announced: bool = False
    query_time: str = ""
    rir: str | None = None
    block: dict[str, Any] | None = None


class RoutingStatus(BaseModel):
    """Current routing status for a resource."""
    resource: str = ""
    query_time: str = ""
    observed_neighbours: int = 0
    visibility: dict[str, Any] = Field(default_factory=dict)
    first_seen: dict[str, Any] | None = None
    last_seen: dict[str, Any] | None = None


class RoutingHistoryEntry(BaseModel):
    """Single entry in routing history."""
    origin: int | None = None
    path: str | None = None
    primary: dict[str, Any] | None = None


class RoutingHistory(BaseModel):
    """Historical routing information."""
    resource: str = ""
    query_starttime: str = ""
    query_endtime: str = ""
    by_origin: list[dict[str, Any]] = Field(default_factory=list)
    prefixes: list[dict[str, Any]] = Field(default_factory=list)


class BGPUpdate(BaseModel):
    """Single BGP update event."""
    timestamp: str = ""
    type: str = ""  # A=announcement, W=withdrawal
    attrs: dict[str, Any] | None = None
    source_id: str = ""
    path: list[int] = Field(default_factory=list)


class BGPUpdates(BaseModel):
    """BGP update activity."""
    resource: str = ""
    query_starttime: str = ""
    query_endtime: str = ""
    updates: list[BGPUpdate] = Field(default_factory=list)
    nr_updates: int = 0


class Prefix(BaseModel):
    """Announced prefix."""
    prefix: str = ""
    timelines: list[dict[str, Any]] = Field(default_factory=list)


class AnnouncedPrefixes(BaseModel):
    """All prefixes announced by an ASN."""
    resource: str = ""
    query_time: str = ""
    prefixes: list[Prefix] = Field(default_factory=list)

    @property
    def ipv4_prefixes(self) -> list[str]:
        return [p.prefix for p in self.prefixes if "." in p.prefix]

    @property
    def ipv6_prefixes(self) -> list[str]:
        return [p.prefix for p in self.prefixes if ":" in p.prefix]

    @property
    def prefix_count(self) -> int:
        return len(self.prefixes)


class ASPathLengthEntry(BaseModel):
    """Path length statistics entry."""
    count: int = 0
    stripped: int = 0
    unstripped: int = 0


class ASPathLength(BaseModel):
    """AS path length statistics."""
    resource: str = ""
    query_time: str = ""
    stats: list[dict[str, Any]] = Field(default_factory=list)


class ROA(BaseModel):
    """RPKI ROA entry."""
    origin: str = ""
    prefix: str = ""
    max_length: int = 0
    ta: str = ""  # Trust Anchor


class RPKIValidation(BaseModel):
    """RPKI validation status."""
    resource: str = ""
    prefix: str = ""
    status: str = ""  # valid, invalid, not-found
    roas: list[ROA] = Field(default_factory=list)
    expected_origin: int | None = None
    observed_origin: int | None = None


class Neighbour(BaseModel):
    """AS neighbour."""
    asn: int
    name: str = ""
    power: int = 0
    v4_peers: int = 0
    v6_peers: int = 0


class ASNeighbours(BaseModel):
    """Neighbouring ASes."""
    resource: str = ""
    query_time: str = ""
    neighbour_counts: dict[str, int] = Field(default_factory=dict)
    neighbours: list[Neighbour] = Field(default_factory=list)

    # Categorized neighbours
    upstreams: list[Neighbour] = Field(default_factory=list)
    downstreams: list[Neighbour] = Field(default_factory=list)
    left: list[Neighbour] = Field(default_factory=list)
    right: list[Neighbour] = Field(default_factory=list)
    uncertain: list[Neighbour] = Field(default_factory=list)

    def __init__(self, **data):
        super().__init__(**data)
        # Parse neighbours into categories if raw neighbours provided
        if self.neighbours and not self.upstreams:
            for n in self.neighbours:
                # This is a simplified heuristic
                if n.power > 0:
                    self.upstreams.append(n)
                else:
                    self.downstreams.append(n)


class RRCPeer(BaseModel):
    """Peer at a Route Reflector Client."""
    asn: int = 0
    ip: str = ""
    prefix: str = ""
    as_path: str = ""
    community: str = ""
    last_update: str = ""


class RRC(BaseModel):
    """Route Reflector Client data."""
    rrc: str = ""
    location: str = ""
    peers: list[RRCPeer] = Field(default_factory=list)


class LookingGlass(BaseModel):
    """Looking glass query results."""
    resource: str = ""
    query_time: str = ""
    rrcs: list[RRC] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
