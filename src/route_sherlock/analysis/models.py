"""
Analysis Layer Models.

Data models for BGP analysis results and reports.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class HealthStatus(str, Enum):
    """Overall health status."""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Risk assessment level."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnomalyType(str, Enum):
    """Types of routing anomalies."""
    PREFIX_HIJACK = "prefix_hijack"
    ROUTE_LEAK = "route_leak"
    PATH_CHANGE = "path_change"
    VISIBILITY_DROP = "visibility_drop"
    RPKI_INVALID = "rpki_invalid"
    MOAS = "moas"  # Multiple Origin AS
    SUBPREFIX_HIJACK = "subprefix_hijack"
    UNUSUAL_PATH_LENGTH = "unusual_path_length"


class RecommendationType(str, Enum):
    """Types of recommendations."""
    PEER_WITH = "peer_with"
    JOIN_IX = "join_ix"
    DEPLOY_RPKI = "deploy_rpki"
    ADD_UPSTREAM = "add_upstream"
    MONITOR_PREFIX = "monitor_prefix"
    UPDATE_IRR = "update_irr"


# ============================================================================
# ASN Analysis Models
# ============================================================================

class ASNIdentity(BaseModel):
    """Basic ASN identity information."""
    asn: int
    name: str = ""
    org_name: str = ""
    country: str = ""
    rir: str = ""
    network_type: str = ""
    website: str = ""


class RoutingFootprint(BaseModel):
    """ASN's routing footprint."""
    ipv4_prefixes: int = 0
    ipv6_prefixes: int = 0
    total_prefixes: int = 0
    ipv4_addresses: int = 0  # Estimated from prefixes
    upstream_count: int = 0
    downstream_count: int = 0
    peer_count: int = 0


class RPKIStatus(BaseModel):
    """RPKI deployment status."""
    has_roas: bool = False
    valid_prefixes: int = 0
    invalid_prefixes: int = 0
    not_found_prefixes: int = 0
    coverage_percent: float = 0.0

    @property
    def is_deployed(self) -> bool:
        return self.has_roas and self.coverage_percent > 50


class ConnectivityProfile(BaseModel):
    """Network connectivity profile."""
    ix_count: int = 0
    facility_count: int = 0
    peering_policy: str = ""
    has_looking_glass: bool = False
    has_route_server: bool = False
    irr_as_set: str = ""
    ixes: list[str] = Field(default_factory=list)
    top_upstreams: list[int] = Field(default_factory=list)


class AtlasCoverage(BaseModel):
    """RIPE Atlas probe coverage."""
    probe_count: int = 0
    connected_probes: int = 0
    anchor_count: int = 0
    countries: list[str] = Field(default_factory=list)


class ASNProfile(BaseModel):
    """Complete ASN profile combining all data sources."""
    identity: ASNIdentity
    footprint: RoutingFootprint
    rpki: RPKIStatus
    connectivity: ConnectivityProfile
    atlas: AtlasCoverage
    health: HealthStatus = HealthStatus.UNKNOWN
    last_updated: datetime = Field(default_factory=datetime.utcnow)

    @property
    def summary(self) -> str:
        """One-line summary of the ASN."""
        return (
            f"AS{self.identity.asn} ({self.identity.name}): "
            f"{self.footprint.total_prefixes} prefixes, "
            f"{self.connectivity.ix_count} IXes, "
            f"RPKI {self.rpki.coverage_percent:.0f}%"
        )


# ============================================================================
# Path Analysis Models
# ============================================================================

class PathHop(BaseModel):
    """Single hop in an AS path."""
    asn: int
    name: str = ""
    position: int = 0
    is_origin: bool = False
    is_destination: bool = False


class ASPath(BaseModel):
    """AS path with analysis."""
    path: list[int]
    hops: list[PathHop] = Field(default_factory=list)
    length: int = 0
    origin_asn: int = 0
    has_prepending: bool = False
    prepend_count: int = 0

    def __init__(self, **data):
        super().__init__(**data)
        if self.path and not self.length:
            self.length = len(self.path)
        if self.path and not self.origin_asn:
            self.origin_asn = self.path[-1] if self.path else 0


class PathAnalysis(BaseModel):
    """Analysis of paths to a destination."""
    destination: str  # Prefix or ASN
    path_count: int = 0
    unique_paths: list[ASPath] = Field(default_factory=list)
    avg_path_length: float = 0.0
    min_path_length: int = 0
    max_path_length: int = 0
    common_transit: list[int] = Field(default_factory=list)  # ASNs seen in most paths
    origin_asns: list[int] = Field(default_factory=list)


class LatencyMeasurement(BaseModel):
    """Latency measurement from Atlas."""
    source_probe_id: int
    source_asn: int | None = None
    source_country: str = ""
    target: str = ""
    min_rtt: float | None = None
    avg_rtt: float | None = None
    max_rtt: float | None = None
    packet_loss: float = 0.0
    timestamp: datetime | None = None


class LatencyAnalysis(BaseModel):
    """Latency analysis results."""
    target: str
    measurement_count: int = 0
    measurements: list[LatencyMeasurement] = Field(default_factory=list)
    global_avg_rtt: float | None = None
    by_country: dict[str, float] = Field(default_factory=dict)
    by_asn: dict[int, float] = Field(default_factory=dict)


# ============================================================================
# Anomaly Detection Models
# ============================================================================

class Anomaly(BaseModel):
    """Detected routing anomaly."""
    type: AnomalyType
    severity: RiskLevel
    resource: str  # Affected prefix or ASN
    description: str
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    details: dict[str, Any] = Field(default_factory=dict)

    # For hijacks/leaks
    expected_origin: int | None = None
    observed_origin: int | None = None

    @property
    def is_critical(self) -> bool:
        return self.severity == RiskLevel.CRITICAL


class AnomalyReport(BaseModel):
    """Report of detected anomalies."""
    resource: str
    scan_time: datetime = Field(default_factory=datetime.utcnow)
    anomalies: list[Anomaly] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW

    @property
    def anomaly_count(self) -> int:
        return len(self.anomalies)

    @property
    def critical_count(self) -> int:
        return sum(1 for a in self.anomalies if a.is_critical)


# ============================================================================
# Peering Analysis Models
# ============================================================================

class PeeringCandidate(BaseModel):
    """Potential peering partner."""
    asn: int
    name: str = ""
    peering_policy: str = ""
    common_ix_count: int = 0
    common_facility_count: int = 0
    common_ixes: list[str] = Field(default_factory=list)
    traffic_ratio: str = ""
    score: float = 0.0  # Calculated suitability score

    @property
    def can_peer_at_ix(self) -> bool:
        return self.common_ix_count > 0


class IXRecommendation(BaseModel):
    """Recommended IX to join."""
    ix_id: int
    ix_name: str
    country: str = ""
    city: str = ""
    member_count: int = 0
    potential_peers: int = 0  # How many of target's upstreams are here
    score: float = 0.0
    reason: str = ""


class PeeringReport(BaseModel):
    """Peering analysis report."""
    asn: int
    name: str = ""
    current_ix_count: int = 0
    current_peer_count: int = 0
    candidates: list[PeeringCandidate] = Field(default_factory=list)
    ix_recommendations: list[IXRecommendation] = Field(default_factory=list)
    estimated_traffic_shift: float = 0.0  # Percent traffic that could be peered


# ============================================================================
# Recommendation Models
# ============================================================================

class Recommendation(BaseModel):
    """Actionable recommendation."""
    type: RecommendationType
    priority: RiskLevel
    title: str
    description: str
    impact: str = ""
    effort: str = ""  # low/medium/high
    details: dict[str, Any] = Field(default_factory=dict)


class AnalysisReport(BaseModel):
    """Complete analysis report for an ASN."""
    asn: int
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    profile: ASNProfile | None = None
    path_analysis: PathAnalysis | None = None
    anomalies: AnomalyReport | None = None
    peering: PeeringReport | None = None
    recommendations: list[Recommendation] = Field(default_factory=list)
    health_score: float = 0.0  # 0-100

    @property
    def summary(self) -> dict[str, Any]:
        return {
            "asn": self.asn,
            "health_score": self.health_score,
            "anomaly_count": self.anomalies.anomaly_count if self.anomalies else 0,
            "recommendation_count": len(self.recommendations),
            "peering_opportunities": len(self.peering.candidates) if self.peering else 0,
        }
