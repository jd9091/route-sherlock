"""
Route Sherlock - BGP Intelligence Tool.

A comprehensive toolkit for BGP routing analysis, combining data from
RIPEstat, RIPE Atlas, and PeeringDB.

Quick Start:
    from route_sherlock import RouteSherlock

    async with RouteSherlock() as sherlock:
        # Profile an ASN
        profile = await sherlock.profile_asn(16509)
        print(profile.summary)

        # Check a prefix
        status = await sherlock.check_prefix("8.8.8.0/24")

        # Find peering opportunities
        peers = await sherlock.find_peers(16509)

Synchronous Usage:
    from route_sherlock import RouteSherlockSync

    sherlock = RouteSherlockSync()
    profile = sherlock.profile_asn(16509)
"""

__version__ = "0.1.0"

from route_sherlock.analysis import (
    RouteSherlock,
    RouteSherlockSync,
    ASNAnalyzer,
    PathAnalyzer,
    PeeringAnalyzer,
    AnalysisReport,
    ASNProfile,
    HealthStatus,
    RiskLevel,
)

from route_sherlock.collectors.ripestat import RIPEstatClient, RIPEstatClientSync
from route_sherlock.collectors.atlas import AtlasClient, AtlasClientSync
from route_sherlock.collectors.peeringdb import PeeringDBClient, PeeringDBClientSync

__all__ = [
    # Main interface
    "RouteSherlock",
    "RouteSherlockSync",
    # Individual analyzers
    "ASNAnalyzer",
    "PathAnalyzer",
    "PeeringAnalyzer",
    # Data collectors
    "RIPEstatClient",
    "RIPEstatClientSync",
    "AtlasClient",
    "AtlasClientSync",
    "PeeringDBClient",
    "PeeringDBClientSync",
    # Models
    "AnalysisReport",
    "ASNProfile",
    "HealthStatus",
    "RiskLevel",
]
