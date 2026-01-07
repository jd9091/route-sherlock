"""
ASN Analyzer.

Comprehensive ASN profiling combining RIPEstat, PeeringDB, and Atlas data.
"""
from __future__ import annotations

import asyncio
from typing import Any

from route_sherlock.collectors.ripestat import RIPEstatClient
from route_sherlock.collectors.peeringdb import PeeringDBClient, PeeringDBNotFoundError
from route_sherlock.collectors.atlas import AtlasClient

from route_sherlock.analysis.models import (
    ASNIdentity,
    ASNProfile,
    AtlasCoverage,
    ConnectivityProfile,
    HealthStatus,
    Recommendation,
    RecommendationType,
    RiskLevel,
    RoutingFootprint,
    RPKIStatus,
)


class ASNAnalyzer:
    """
    Analyzer for comprehensive ASN profiling.

    Combines data from multiple sources to build a complete picture
    of an autonomous system's routing presence and health.

    Example:
        async with ASNAnalyzer() as analyzer:
            profile = await analyzer.get_profile(16509)
            print(profile.summary)
    """

    def __init__(
        self,
        ripestat: RIPEstatClient | None = None,
        peeringdb: PeeringDBClient | None = None,
        atlas: AtlasClient | None = None,
    ):
        """
        Initialize analyzer with optional pre-configured clients.

        Args:
            ripestat: RIPEstat client instance
            peeringdb: PeeringDB client instance
            atlas: Atlas client instance
        """
        self._ripestat = ripestat
        self._peeringdb = peeringdb
        self._atlas = atlas
        self._owns_clients = False

    async def __aenter__(self) -> "ASNAnalyzer":
        if not self._ripestat:
            self._ripestat = RIPEstatClient()
            await self._ripestat.__aenter__()
        if not self._peeringdb:
            self._peeringdb = PeeringDBClient()
            await self._peeringdb.__aenter__()
        if not self._atlas:
            self._atlas = AtlasClient()
            await self._atlas.__aenter__()
        self._owns_clients = True
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._owns_clients:
            if self._ripestat:
                await self._ripestat.__aexit__(exc_type, exc_val, exc_tb)
            if self._peeringdb:
                await self._peeringdb.__aexit__(exc_type, exc_val, exc_tb)
            if self._atlas:
                await self._atlas.__aexit__(exc_type, exc_val, exc_tb)

    async def get_identity(self, asn: int) -> ASNIdentity:
        """
        Get basic identity information for an ASN.

        Args:
            asn: AS number

        Returns:
            ASNIdentity with name, org, country, etc.
        """
        identity = ASNIdentity(asn=asn)

        # Get from RIPEstat
        try:
            overview = await self._ripestat.get_as_overview(str(asn))
            identity.name = overview.holder or ""
            identity.rir = overview.rir or ""
        except Exception:
            pass

        # Enrich from PeeringDB
        try:
            network = await self._peeringdb.get_network_by_asn(asn)
            if not identity.name:
                identity.name = network.name
            identity.network_type = network.info_type
            identity.website = network.website

            if network.org_id:
                try:
                    org = await self._peeringdb.get_organization(network.org_id)
                    identity.org_name = org.name
                    identity.country = org.country
                except Exception:
                    pass
        except PeeringDBNotFoundError:
            pass

        return identity

    async def get_routing_footprint(self, asn: int) -> RoutingFootprint:
        """
        Get routing footprint for an ASN.

        Args:
            asn: AS number

        Returns:
            RoutingFootprint with prefix counts and neighbor info
        """
        footprint = RoutingFootprint()

        # Get prefix counts from RIPEstat
        try:
            prefixes = await self._ripestat.get_announced_prefixes(str(asn))
            footprint.ipv4_prefixes = len(prefixes.ipv4_prefixes)
            footprint.ipv6_prefixes = len(prefixes.ipv6_prefixes)
            footprint.total_prefixes = prefixes.prefix_count

            # Estimate IPv4 addresses from prefixes
            total_ips = 0
            for p in prefixes.ipv4_prefixes:
                try:
                    prefix_len = int(p.split("/")[1])
                    total_ips += 2 ** (32 - prefix_len)
                except (IndexError, ValueError):
                    pass
            footprint.ipv4_addresses = total_ips
        except Exception:
            pass

        # Get neighbor counts
        try:
            neighbours = await self._ripestat.get_as_neighbours(str(asn))
            footprint.upstream_count = len(neighbours.upstreams)
            footprint.downstream_count = len(neighbours.downstreams)
            footprint.peer_count = len(neighbours.left) + len(neighbours.right)
        except Exception:
            pass

        return footprint

    async def get_rpki_status(self, asn: int) -> RPKIStatus:
        """
        Get RPKI deployment status for an ASN.

        Args:
            asn: AS number

        Returns:
            RPKIStatus with ROA coverage information
        """
        status = RPKIStatus()

        try:
            rpki_data = await self._ripestat.check_rpki_status(str(asn))

            valid = len(rpki_data.get("valid", []))
            invalid = len(rpki_data.get("invalid", []))
            not_found = len(rpki_data.get("not_found", []))
            total = valid + invalid + not_found

            status.valid_prefixes = valid
            status.invalid_prefixes = invalid
            status.not_found_prefixes = not_found
            status.has_roas = valid > 0

            if total > 0:
                status.coverage_percent = (valid / total) * 100
        except Exception:
            pass

        return status

    async def get_connectivity_profile(self, asn: int) -> ConnectivityProfile:
        """
        Get connectivity profile from PeeringDB.

        Args:
            asn: AS number

        Returns:
            ConnectivityProfile with IX/facility presence
        """
        profile = ConnectivityProfile()

        try:
            presence = await self._peeringdb.get_network_presence(asn)
            profile.ix_count = presence.ix_count
            profile.facility_count = presence.facility_count
            profile.ixes = [ix.name for ix in presence.exchanges[:10]]

            network = await self._peeringdb.get_network_by_asn(asn)
            profile.peering_policy = network.policy_general
            profile.has_looking_glass = bool(network.looking_glass)
            profile.has_route_server = bool(network.route_server)
            profile.irr_as_set = network.irr_as_set
        except PeeringDBNotFoundError:
            pass
        except Exception:
            pass

        # Get top upstreams from RIPEstat
        try:
            upstreams = await self._ripestat.get_upstream_asns(str(asn))
            profile.top_upstreams = upstreams[:5]
        except Exception:
            pass

        return profile

    async def get_atlas_coverage(self, asn: int) -> AtlasCoverage:
        """
        Get RIPE Atlas probe coverage for an ASN.

        Args:
            asn: AS number

        Returns:
            AtlasCoverage with probe counts
        """
        coverage = AtlasCoverage()

        try:
            data = await self._atlas.get_asn_coverage(asn)
            coverage.probe_count = data.get("probe_count", 0)
            coverage.connected_probes = data.get("connected_probes", 0)
            coverage.anchor_count = data.get("anchor_count", 0)
            coverage.countries = data.get("countries", [])
        except Exception:
            pass

        return coverage

    async def get_profile(self, asn: int) -> ASNProfile:
        """
        Get complete ASN profile.

        Fetches data from all sources in parallel for efficiency.

        Args:
            asn: AS number

        Returns:
            Complete ASNProfile
        """
        # Fetch all data in parallel
        identity_task = self.get_identity(asn)
        footprint_task = self.get_routing_footprint(asn)
        rpki_task = self.get_rpki_status(asn)
        connectivity_task = self.get_connectivity_profile(asn)
        atlas_task = self.get_atlas_coverage(asn)

        identity, footprint, rpki, connectivity, atlas = await asyncio.gather(
            identity_task,
            footprint_task,
            rpki_task,
            connectivity_task,
            atlas_task,
        )

        # Determine health status
        health = self._assess_health(footprint, rpki, connectivity)

        return ASNProfile(
            identity=identity,
            footprint=footprint,
            rpki=rpki,
            connectivity=connectivity,
            atlas=atlas,
            health=health,
        )

    def _assess_health(
        self,
        footprint: RoutingFootprint,
        rpki: RPKIStatus,
        connectivity: ConnectivityProfile,
    ) -> HealthStatus:
        """Assess overall health based on profile data."""
        issues = 0

        # Check for RPKI issues
        if rpki.invalid_prefixes > 0:
            issues += 2
        elif not rpki.has_roas:
            issues += 1

        # Check for low redundancy
        if footprint.upstream_count < 2:
            issues += 1

        # Check for single IX presence
        if connectivity.ix_count == 1:
            issues += 1
        elif connectivity.ix_count == 0 and footprint.total_prefixes > 0:
            issues += 1

        if issues >= 3:
            return HealthStatus.CRITICAL
        elif issues >= 2:
            return HealthStatus.WARNING
        elif issues == 0:
            return HealthStatus.HEALTHY
        else:
            return HealthStatus.WARNING

    async def get_recommendations(self, asn: int) -> list[Recommendation]:
        """
        Generate recommendations for an ASN.

        Args:
            asn: AS number

        Returns:
            List of actionable recommendations
        """
        profile = await self.get_profile(asn)
        recommendations = []

        # RPKI recommendations
        if profile.rpki.invalid_prefixes > 0:
            recommendations.append(Recommendation(
                type=RecommendationType.DEPLOY_RPKI,
                priority=RiskLevel.HIGH,
                title="Fix invalid RPKI ROAs",
                description=f"{profile.rpki.invalid_prefixes} prefixes have invalid RPKI status",
                impact="Prevents route filtering by RPKI-validating networks",
                effort="medium",
            ))
        elif not profile.rpki.has_roas:
            recommendations.append(Recommendation(
                type=RecommendationType.DEPLOY_RPKI,
                priority=RiskLevel.MEDIUM,
                title="Deploy RPKI ROAs",
                description="No RPKI ROAs found for this network",
                impact="Protects against prefix hijacking",
                effort="low",
            ))
        elif profile.rpki.coverage_percent < 100:
            recommendations.append(Recommendation(
                type=RecommendationType.DEPLOY_RPKI,
                priority=RiskLevel.LOW,
                title="Complete RPKI coverage",
                description=f"Only {profile.rpki.coverage_percent:.0f}% of prefixes covered",
                impact="Full protection against hijacking",
                effort="low",
            ))

        # Connectivity recommendations
        if profile.footprint.upstream_count < 2:
            recommendations.append(Recommendation(
                type=RecommendationType.ADD_UPSTREAM,
                priority=RiskLevel.HIGH,
                title="Add upstream diversity",
                description="Single upstream creates single point of failure",
                impact="Improves resilience and redundancy",
                effort="high",
            ))

        if profile.connectivity.ix_count == 0 and profile.footprint.total_prefixes > 10:
            recommendations.append(Recommendation(
                type=RecommendationType.JOIN_IX,
                priority=RiskLevel.MEDIUM,
                title="Consider joining an IX",
                description="No IX presence detected",
                impact="Reduces latency and transit costs through peering",
                effort="medium",
            ))

        # IRR recommendation
        if not profile.connectivity.irr_as_set:
            recommendations.append(Recommendation(
                type=RecommendationType.UPDATE_IRR,
                priority=RiskLevel.LOW,
                title="Register IRR as-set",
                description="No IRR as-set found in PeeringDB",
                impact="Enables automated prefix filtering by peers",
                effort="low",
            ))

        return recommendations

    async def compare_asns(
        self,
        asn1: int,
        asn2: int,
    ) -> dict[str, Any]:
        """
        Compare two ASNs side by side.

        Args:
            asn1: First AS number
            asn2: Second AS number

        Returns:
            Comparison dict with both profiles and differences
        """
        profile1, profile2 = await asyncio.gather(
            self.get_profile(asn1),
            self.get_profile(asn2),
        )

        return {
            "asn1": {
                "asn": asn1,
                "name": profile1.identity.name,
                "prefixes": profile1.footprint.total_prefixes,
                "upstreams": profile1.footprint.upstream_count,
                "ix_count": profile1.connectivity.ix_count,
                "rpki_coverage": profile1.rpki.coverage_percent,
                "health": profile1.health.value,
            },
            "asn2": {
                "asn": asn2,
                "name": profile2.identity.name,
                "prefixes": profile2.footprint.total_prefixes,
                "upstreams": profile2.footprint.upstream_count,
                "ix_count": profile2.connectivity.ix_count,
                "rpki_coverage": profile2.rpki.coverage_percent,
                "health": profile2.health.value,
            },
            "comparison": {
                "larger_by_prefixes": asn1 if profile1.footprint.total_prefixes > profile2.footprint.total_prefixes else asn2,
                "more_connected": asn1 if profile1.connectivity.ix_count > profile2.connectivity.ix_count else asn2,
                "better_rpki": asn1 if profile1.rpki.coverage_percent > profile2.rpki.coverage_percent else asn2,
            },
        }
