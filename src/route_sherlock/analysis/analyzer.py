"""
Route Sherlock Analyzer.

Main orchestrator combining all analysis capabilities into a unified interface.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

from route_sherlock.collectors.ripestat import RIPEstatClient
from route_sherlock.collectors.peeringdb import PeeringDBClient
from route_sherlock.collectors.atlas import AtlasClient

from route_sherlock.analysis.asn import ASNAnalyzer
from route_sherlock.analysis.paths import PathAnalyzer
from route_sherlock.analysis.peering import PeeringAnalyzer

from route_sherlock.analysis.models import (
    AnalysisReport,
    HealthStatus,
    Recommendation,
    RecommendationType,
    RiskLevel,
)


class RouteSherlock:
    """
    Main BGP intelligence analyzer.

    Provides a unified interface for ASN profiling, path analysis,
    anomaly detection, and peering optimization.

    Example:
        async with RouteSherlock() as sherlock:
            # Quick ASN lookup
            profile = await sherlock.profile_asn(16509)
            print(profile.summary)

            # Full analysis report
            report = await sherlock.full_analysis(16509)
            for rec in report.recommendations:
                print(f"[{rec.priority}] {rec.title}")

            # Peering opportunity
            opportunity = await sherlock.peering_opportunity(16509, 13335)
    """

    def __init__(
        self,
        ripestat_cache_ttl: int = 3600,
        peeringdb_cache_ttl: int = 3600,
        atlas_cache_ttl: int = 300,
        atlas_api_key: str | None = None,
        peeringdb_api_key: str | None = None,
    ):
        """
        Initialize Route Sherlock.

        Args:
            ripestat_cache_ttl: Cache TTL for RIPEstat responses
            peeringdb_cache_ttl: Cache TTL for PeeringDB responses
            atlas_cache_ttl: Cache TTL for Atlas responses
            atlas_api_key: RIPE Atlas API key (optional)
            peeringdb_api_key: PeeringDB API key (optional)
        """
        self._ripestat: RIPEstatClient | None = None
        self._peeringdb: PeeringDBClient | None = None
        self._atlas: AtlasClient | None = None

        self._ripestat_ttl = ripestat_cache_ttl
        self._peeringdb_ttl = peeringdb_cache_ttl
        self._atlas_ttl = atlas_cache_ttl
        self._atlas_key = atlas_api_key
        self._peeringdb_key = peeringdb_api_key

        self._asn_analyzer: ASNAnalyzer | None = None
        self._path_analyzer: PathAnalyzer | None = None
        self._peering_analyzer: PeeringAnalyzer | None = None

    async def __aenter__(self) -> "RouteSherlock":
        # Initialize clients
        self._ripestat = RIPEstatClient(cache_ttl=self._ripestat_ttl)
        self._peeringdb = PeeringDBClient(
            api_key=self._peeringdb_key,
            cache_ttl=self._peeringdb_ttl,
        )
        self._atlas = AtlasClient(
            api_key=self._atlas_key,
            cache_ttl=self._atlas_ttl,
        )

        await self._ripestat.__aenter__()
        await self._peeringdb.__aenter__()
        await self._atlas.__aenter__()

        # Initialize analyzers with shared clients
        self._asn_analyzer = ASNAnalyzer(
            ripestat=self._ripestat,
            peeringdb=self._peeringdb,
            atlas=self._atlas,
        )
        self._path_analyzer = PathAnalyzer(
            ripestat=self._ripestat,
            atlas=self._atlas,
        )
        self._peering_analyzer = PeeringAnalyzer(
            ripestat=self._ripestat,
            peeringdb=self._peeringdb,
        )

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._ripestat:
            await self._ripestat.__aexit__(exc_type, exc_val, exc_tb)
        if self._peeringdb:
            await self._peeringdb.__aexit__(exc_type, exc_val, exc_tb)
        if self._atlas:
            await self._atlas.__aexit__(exc_type, exc_val, exc_tb)

    # ========================================================================
    # Quick Lookups
    # ========================================================================

    async def profile_asn(self, asn: int) -> Any:
        """
        Get complete ASN profile.

        Args:
            asn: AS number

        Returns:
            ASNProfile with identity, footprint, RPKI, connectivity
        """
        return await self._asn_analyzer.get_profile(asn)

    async def lookup(self, resource: str) -> dict[str, Any]:
        """
        Quick lookup for any resource (ASN or prefix).

        Args:
            resource: ASN (e.g., "AS16509", "16509") or prefix (e.g., "8.8.8.0/24")

        Returns:
            Dict with relevant information
        """
        resource = resource.strip().upper()

        # Determine resource type
        if resource.startswith("AS") or resource.isdigit():
            asn = int(resource.replace("AS", ""))
            profile = await self.profile_asn(asn)
            return {
                "type": "asn",
                "asn": asn,
                "name": profile.identity.name,
                "org": profile.identity.org_name,
                "country": profile.identity.country,
                "prefixes_v4": profile.footprint.ipv4_prefixes,
                "prefixes_v6": profile.footprint.ipv6_prefixes,
                "upstreams": profile.footprint.upstream_count,
                "ix_count": profile.connectivity.ix_count,
                "rpki_coverage": f"{profile.rpki.coverage_percent:.0f}%",
                "health": profile.health.value,
            }
        else:
            # Treat as prefix
            path_analysis = await self._path_analyzer.analyze_paths(resource)
            anomalies = await self._path_analyzer.detect_anomalies(resource)

            return {
                "type": "prefix",
                "prefix": resource,
                "origin_asns": path_analysis.origin_asns,
                "path_count": path_analysis.path_count,
                "avg_path_length": round(path_analysis.avg_path_length, 1),
                "common_transit": path_analysis.common_transit[:5],
                "anomaly_count": anomalies.anomaly_count,
                "risk_level": anomalies.risk_level.value,
            }

    async def whois(self, asn: int) -> dict[str, Any]:
        """
        Get WHOIS-like information for an ASN.

        Args:
            asn: AS number

        Returns:
            Dict with identity and contact info
        """
        identity = await self._asn_analyzer.get_identity(asn)

        try:
            network = await self._peeringdb.get_network_by_asn(asn)
            return {
                "asn": asn,
                "name": identity.name,
                "org": identity.org_name,
                "country": identity.country,
                "rir": identity.rir,
                "type": network.info_type,
                "website": network.website,
                "looking_glass": network.looking_glass or None,
                "peering_policy": network.policy_general,
                "policy_url": network.policy_url or None,
                "irr_as_set": network.irr_as_set or None,
            }
        except Exception:
            return {
                "asn": asn,
                "name": identity.name,
                "org": identity.org_name,
                "country": identity.country,
                "rir": identity.rir,
            }

    # ========================================================================
    # Analysis Methods
    # ========================================================================

    async def full_analysis(self, asn: int) -> AnalysisReport:
        """
        Run comprehensive analysis for an ASN.

        Includes profile, path analysis, anomaly detection,
        peering opportunities, and recommendations.

        Args:
            asn: AS number

        Returns:
            Complete AnalysisReport
        """
        report = AnalysisReport(asn=asn)

        # Run all analyses in parallel
        profile_task = self._asn_analyzer.get_profile(asn)
        peering_task = self._peering_analyzer.get_peering_report(asn)
        recommendations_task = self._asn_analyzer.get_recommendations(asn)

        profile, peering, recommendations = await asyncio.gather(
            profile_task,
            peering_task,
            recommendations_task,
        )

        report.profile = profile
        report.peering = peering
        report.recommendations = recommendations

        # Get path analysis for announced prefixes
        if profile.footprint.total_prefixes > 0:
            try:
                prefixes = await self._ripestat.get_announced_prefixes(str(asn))
                if prefixes.prefixes:
                    # Analyze first prefix as sample
                    sample_prefix = prefixes.prefixes[0].prefix
                    report.path_analysis = await self._path_analyzer.analyze_paths(sample_prefix)
                    report.anomalies = await self._path_analyzer.detect_anomalies(sample_prefix)
            except Exception:
                pass

        # Calculate health score
        report.health_score = self._calculate_health_score(report)

        return report

    def _calculate_health_score(self, report: AnalysisReport) -> float:
        """Calculate overall health score (0-100)."""
        score = 100.0

        if not report.profile:
            return 50.0

        # RPKI scoring (up to -30)
        if report.profile.rpki.invalid_prefixes > 0:
            score -= 30
        elif not report.profile.rpki.has_roas:
            score -= 20
        elif report.profile.rpki.coverage_percent < 100:
            score -= (100 - report.profile.rpki.coverage_percent) * 0.1

        # Connectivity scoring (up to -20)
        if report.profile.footprint.upstream_count < 2:
            score -= 15
        if report.profile.connectivity.ix_count == 0:
            score -= 10

        # Anomaly scoring (up to -30)
        if report.anomalies:
            if report.anomalies.risk_level == RiskLevel.CRITICAL:
                score -= 30
            elif report.anomalies.risk_level == RiskLevel.HIGH:
                score -= 20
            elif report.anomalies.risk_level == RiskLevel.MEDIUM:
                score -= 10

        # Health status adjustment
        if report.profile.health == HealthStatus.CRITICAL:
            score = min(score, 40)
        elif report.profile.health == HealthStatus.WARNING:
            score = min(score, 70)

        return max(0, min(100, score))

    async def check_prefix(self, prefix: str) -> dict[str, Any]:
        """
        Check a prefix for issues.

        Args:
            prefix: IP prefix (e.g., "8.8.8.0/24")

        Returns:
            Dict with prefix status and any issues
        """
        path_analysis, anomalies = await asyncio.gather(
            self._path_analyzer.analyze_paths(prefix),
            self._path_analyzer.detect_anomalies(prefix),
        )

        return {
            "prefix": prefix,
            "origin_asns": path_analysis.origin_asns,
            "is_moas": len(path_analysis.origin_asns) > 1,
            "path_count": path_analysis.path_count,
            "avg_path_length": round(path_analysis.avg_path_length, 1),
            "anomalies": [
                {
                    "type": a.type.value,
                    "severity": a.severity.value,
                    "description": a.description,
                }
                for a in anomalies.anomalies
            ],
            "risk_level": anomalies.risk_level.value,
            "is_healthy": anomalies.anomaly_count == 0,
        }

    async def monitor_changes(
        self,
        resource: str,
        hours: int = 24,
    ) -> dict[str, Any]:
        """
        Monitor routing changes for a resource.

        Args:
            resource: ASN or prefix
            hours: Hours to look back

        Returns:
            Dict with change summary
        """
        return await self._path_analyzer.get_path_changes(resource, hours)

    # ========================================================================
    # Peering Methods
    # ========================================================================

    async def peering_opportunity(
        self,
        asn1: int,
        asn2: int,
    ) -> dict[str, Any]:
        """
        Analyze peering opportunity between two ASNs.

        Args:
            asn1: First AS number
            asn2: Second AS number

        Returns:
            Peering opportunity analysis
        """
        return await self._peering_analyzer.analyze_peering_opportunity(asn1, asn2)

    async def find_peers(
        self,
        asn: int,
        max_results: int = 20,
    ) -> list[dict[str, Any]]:
        """
        Find potential peering partners.

        Args:
            asn: AS number
            max_results: Maximum results

        Returns:
            List of peering candidates
        """
        candidates = await self._peering_analyzer.find_peering_candidates(asn, max_results)

        return [
            {
                "asn": c.asn,
                "name": c.name,
                "policy": c.peering_policy,
                "common_ixes": c.common_ixes,
                "score": round(c.score, 1),
            }
            for c in candidates
        ]

    async def recommend_ix(self, asn: int) -> list[dict[str, Any]]:
        """
        Get IX recommendations for an ASN.

        Args:
            asn: AS number

        Returns:
            List of IX recommendations
        """
        recs = await self._peering_analyzer.recommend_ixes(asn)

        return [
            {
                "ix_name": r.ix_name,
                "country": r.country,
                "city": r.city,
                "members": r.member_count,
                "potential_peers": r.potential_peers,
                "reason": r.reason,
                "score": round(r.score, 1),
            }
            for r in recs
        ]

    # ========================================================================
    # Comparison Methods
    # ========================================================================

    async def compare(
        self,
        asn1: int,
        asn2: int,
    ) -> dict[str, Any]:
        """
        Compare two ASNs.

        Args:
            asn1: First AS number
            asn2: Second AS number

        Returns:
            Side-by-side comparison
        """
        return await self._asn_analyzer.compare_asns(asn1, asn2)

    async def measure_latency(
        self,
        target: str,
        from_asn: int | None = None,
        from_country: str | None = None,
    ) -> dict[str, Any]:
        """
        Measure latency to a target.

        Args:
            target: Target IP or hostname
            from_asn: Source ASN filter
            from_country: Source country filter

        Returns:
            Latency measurements
        """
        analysis = await self._path_analyzer.measure_latency(
            target,
            source_asn=from_asn,
            source_country=from_country,
        )

        return {
            "target": target,
            "measurement_count": analysis.measurement_count,
            "global_avg_rtt_ms": round(analysis.global_avg_rtt, 2) if analysis.global_avg_rtt else None,
            "by_country": {
                country: round(rtt, 2)
                for country, rtt in sorted(
                    analysis.by_country.items(),
                    key=lambda x: x[1],
                )[:10]
            },
        }

    # ========================================================================
    # Utility Methods
    # ========================================================================

    async def health_check(self) -> dict[str, bool]:
        """
        Check connectivity to all data sources.

        Returns:
            Dict with service status
        """
        results = {}

        # Check RIPEstat
        try:
            await self._ripestat.get_as_overview("AS13335")
            results["ripestat"] = True
        except Exception:
            results["ripestat"] = False

        # Check PeeringDB
        try:
            await self._peeringdb.get_network_by_asn(13335)
            results["peeringdb"] = True
        except Exception:
            results["peeringdb"] = False

        # Check Atlas
        try:
            await self._atlas.get_probe(1)
            results["atlas"] = True
        except Exception:
            results["atlas"] = False

        results["all_healthy"] = all(results.values())
        return results


# ============================================================================
# Synchronous Wrapper
# ============================================================================

class RouteSherlockSync:
    """
    Synchronous wrapper for Route Sherlock.

    Example:
        sherlock = RouteSherlockSync()
        profile = sherlock.profile_asn(16509)
        print(profile.summary)
    """

    def __init__(self, **kwargs):
        self._kwargs = kwargs

    def _run(self, coro):
        async def _inner():
            async with RouteSherlock(**self._kwargs) as sherlock:
                return await coro(sherlock)
        return asyncio.run(_inner())

    def profile_asn(self, asn: int):
        return self._run(lambda s: s.profile_asn(asn))

    def lookup(self, resource: str):
        return self._run(lambda s: s.lookup(resource))

    def whois(self, asn: int):
        return self._run(lambda s: s.whois(asn))

    def full_analysis(self, asn: int):
        return self._run(lambda s: s.full_analysis(asn))

    def check_prefix(self, prefix: str):
        return self._run(lambda s: s.check_prefix(prefix))

    def peering_opportunity(self, asn1: int, asn2: int):
        return self._run(lambda s: s.peering_opportunity(asn1, asn2))

    def find_peers(self, asn: int, max_results: int = 20):
        return self._run(lambda s: s.find_peers(asn, max_results))

    def recommend_ix(self, asn: int):
        return self._run(lambda s: s.recommend_ix(asn))

    def compare(self, asn1: int, asn2: int):
        return self._run(lambda s: s.compare(asn1, asn2))

    def health_check(self):
        return self._run(lambda s: s.health_check())
