"""
Peering Analyzer.

Analyze peering opportunities, IX recommendations, and interconnection strategy.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from typing import Any

from route_sherlock.collectors.ripestat import RIPEstatClient
from route_sherlock.collectors.peeringdb import PeeringDBClient, PeeringDBNotFoundError

from route_sherlock.analysis.models import (
    IXRecommendation,
    PeeringCandidate,
    PeeringReport,
)


class PeeringAnalyzer:
    """
    Analyzer for peering strategy and interconnection optimization.

    Identifies peering opportunities, recommends IXes to join,
    and analyzes traffic patterns.

    Example:
        async with PeeringAnalyzer() as analyzer:
            report = await analyzer.get_peering_report(16509)
            for candidate in report.candidates[:5]:
                print(f"Peer with AS{candidate.asn} at {candidate.common_ixes}")
    """

    def __init__(
        self,
        ripestat: RIPEstatClient | None = None,
        peeringdb: PeeringDBClient | None = None,
    ):
        """
        Initialize analyzer with optional pre-configured clients.

        Args:
            ripestat: RIPEstat client instance
            peeringdb: PeeringDB client instance
        """
        self._ripestat = ripestat
        self._peeringdb = peeringdb
        self._owns_clients = False

    async def __aenter__(self) -> "PeeringAnalyzer":
        if not self._ripestat:
            self._ripestat = RIPEstatClient()
            await self._ripestat.__aenter__()
        if not self._peeringdb:
            self._peeringdb = PeeringDBClient()
            await self._peeringdb.__aenter__()
        self._owns_clients = True
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._owns_clients:
            if self._ripestat:
                await self._ripestat.__aexit__(exc_type, exc_val, exc_tb)
            if self._peeringdb:
                await self._peeringdb.__aexit__(exc_type, exc_val, exc_tb)

    # ========================================================================
    # Peering Candidate Discovery
    # ========================================================================

    async def find_peering_candidates(
        self,
        asn: int,
        max_candidates: int = 20,
    ) -> list[PeeringCandidate]:
        """
        Find potential peering partners for an ASN.

        Identifies networks at common IXes with open/selective peering.

        Args:
            asn: AS number
            max_candidates: Maximum candidates to return

        Returns:
            List of PeeringCandidate sorted by score
        """
        candidates: list[PeeringCandidate] = []

        try:
            # Get target network's IX presence
            target_ixlans = await self._peeringdb.get_network_ixlans(asn)
            target_ix_ids = set(c.ix_id for c in target_ixlans)

            if not target_ix_ids:
                return candidates

            # Get upstreams from RIPEstat (good peering targets)
            upstream_asns = set()
            try:
                neighbours = await self._ripestat.get_as_neighbours(str(asn))
                upstream_asns = set(n.asn for n in neighbours.upstreams)
            except Exception:
                pass

            # For each IX, find networks with good peering policy
            seen_asns: set[int] = set()
            candidate_map: dict[int, PeeringCandidate] = {}

            for ix_id in list(target_ix_ids)[:10]:  # Limit IX scanning
                try:
                    members = await self._peeringdb.get_ix_members(ix_id)
                    ix = await self._peeringdb.get_ix(ix_id)

                    for member in members:
                        if member.asn == asn:
                            continue
                        if member.asn in seen_asns:
                            # Update existing candidate
                            if member.asn in candidate_map:
                                candidate_map[member.asn].common_ix_count += 1
                                candidate_map[member.asn].common_ixes.append(ix.name)
                            continue

                        seen_asns.add(member.asn)

                        # Get network details
                        try:
                            network = await self._peeringdb.get_network_by_asn(member.asn)

                            # Filter by peering policy
                            if network.policy_general.lower() not in ("open", "selective"):
                                continue

                            candidate = PeeringCandidate(
                                asn=member.asn,
                                name=network.name,
                                peering_policy=network.policy_general,
                                common_ix_count=1,
                                common_ixes=[ix.name],
                                traffic_ratio=network.info_ratio,
                                score=0.0,
                            )
                            candidate_map[member.asn] = candidate

                        except PeeringDBNotFoundError:
                            continue

                    await asyncio.sleep(0.05)  # Rate limit

                except Exception:
                    continue

            candidates = list(candidate_map.values())

            # Score candidates
            for c in candidates:
                c.score = self._score_candidate(c, upstream_asns)

            # Sort by score
            candidates.sort(key=lambda x: x.score, reverse=True)

        except PeeringDBNotFoundError:
            pass

        return candidates[:max_candidates]

    def _score_candidate(
        self,
        candidate: PeeringCandidate,
        upstream_asns: set[int],
    ) -> float:
        """
        Score a peering candidate.

        Factors:
        - Open peering policy (+2)
        - Multiple common IXes (+1 per IX)
        - Is current upstream (+3) - high value target
        - Traffic ratio compatibility (+1)
        """
        score = 0.0

        # Policy score
        if candidate.peering_policy.lower() == "open":
            score += 2.0
        elif candidate.peering_policy.lower() == "selective":
            score += 1.0

        # IX count score
        score += candidate.common_ix_count * 1.0

        # Upstream bonus
        if candidate.asn in upstream_asns:
            score += 3.0

        # Traffic ratio (balanced is good)
        if candidate.traffic_ratio.lower() in ("balanced", "mostly inbound"):
            score += 1.0

        return score

    async def find_common_peers(
        self,
        asn1: int,
        asn2: int,
    ) -> list[int]:
        """
        Find networks that peer with both given ASNs.

        Useful for understanding shared connectivity.

        Args:
            asn1: First AS number
            asn2: Second AS number

        Returns:
            List of ASNs that peer with both
        """
        try:
            # Get IX connections for both
            conn1 = await self._peeringdb.get_network_ixlans(asn1)
            conn2 = await self._peeringdb.get_network_ixlans(asn2)

            # Find common IXes
            ix_ids1 = set(c.ix_id for c in conn1)
            ix_ids2 = set(c.ix_id for c in conn2)
            common_ix_ids = ix_ids1 & ix_ids2

            if not common_ix_ids:
                return []

            # Get all members at common IXes
            asns_at_1: set[int] = set()
            asns_at_2: set[int] = set()

            for ix_id in common_ix_ids:
                members = await self._peeringdb.get_ix_members(ix_id)
                member_asns = set(m.asn for m in members)

                if asn1 in member_asns:
                    asns_at_1.update(member_asns)
                if asn2 in member_asns:
                    asns_at_2.update(member_asns)

            # Find overlap (excluding the two input ASNs)
            common = asns_at_1 & asns_at_2
            common.discard(asn1)
            common.discard(asn2)

            return sorted(common)

        except Exception:
            return []

    # ========================================================================
    # IX Recommendations
    # ========================================================================

    async def recommend_ixes(
        self,
        asn: int,
        max_recommendations: int = 10,
    ) -> list[IXRecommendation]:
        """
        Recommend Internet Exchanges for an ASN to join.

        Analyzes where the network's upstreams and desired peers are present.

        Args:
            asn: AS number
            max_recommendations: Maximum recommendations

        Returns:
            List of IXRecommendation sorted by score
        """
        recommendations: list[IXRecommendation] = []

        try:
            # Get current IX presence
            current_ixlans = await self._peeringdb.get_network_ixlans(asn)
            current_ix_ids = set(c.ix_id for c in current_ixlans)

            # Get upstreams
            upstream_asns: set[int] = set()
            try:
                neighbours = await self._ripestat.get_as_neighbours(str(asn))
                upstream_asns = set(n.asn for n in neighbours.upstreams)
            except Exception:
                pass

            # Find where upstreams are present
            ix_upstream_count: Counter[int] = Counter()

            for upstream_asn in list(upstream_asns)[:20]:
                try:
                    upstream_ixlans = await self._peeringdb.get_network_ixlans(upstream_asn)
                    for ixlan in upstream_ixlans:
                        if ixlan.ix_id not in current_ix_ids:
                            ix_upstream_count[ixlan.ix_id] += 1
                    await asyncio.sleep(0.05)
                except Exception:
                    continue

            # Get IX details and create recommendations
            for ix_id, upstream_count in ix_upstream_count.most_common(max_recommendations * 2):
                try:
                    ix = await self._peeringdb.get_ix(ix_id)

                    # Skip very small IXes
                    if ix.member_count < 10:
                        continue

                    score = self._score_ix(ix, upstream_count, len(upstream_asns))

                    reason = f"{upstream_count} of your upstreams present"
                    if ix.member_count > 100:
                        reason += f", {ix.member_count} total members"

                    recommendations.append(IXRecommendation(
                        ix_id=ix_id,
                        ix_name=ix.name,
                        country=ix.country,
                        city=ix.city,
                        member_count=ix.member_count,
                        potential_peers=upstream_count,
                        score=score,
                        reason=reason,
                    ))

                except Exception:
                    continue

            # Sort by score
            recommendations.sort(key=lambda x: x.score, reverse=True)

        except PeeringDBNotFoundError:
            pass

        return recommendations[:max_recommendations]

    def _score_ix(
        self,
        ix: Any,
        upstream_count: int,
        total_upstreams: int,
    ) -> float:
        """Score an IX recommendation."""
        score = 0.0

        # Upstream coverage
        if total_upstreams > 0:
            coverage = upstream_count / total_upstreams
            score += coverage * 5.0

        # Size bonus
        if ix.member_count > 500:
            score += 3.0
        elif ix.member_count > 100:
            score += 2.0
        elif ix.member_count > 50:
            score += 1.0

        # Raw upstream count
        score += upstream_count * 0.5

        return score

    async def get_ix_presence_analysis(self, asn: int) -> dict[str, Any]:
        """
        Analyze current IX presence and gaps.

        Args:
            asn: AS number

        Returns:
            Analysis dict with current presence and gaps
        """
        try:
            presence = await self._peeringdb.get_network_presence(asn)

            # Get upstream presence for comparison
            upstream_asns: list[int] = []
            try:
                neighbours = await self._ripestat.get_as_neighbours(str(asn))
                upstream_asns = [n.asn for n in neighbours.upstreams[:10]]
            except Exception:
                pass

            # Count IX overlap with upstreams
            current_ix_ids = set(ix.id for ix in presence.exchanges)
            upstream_ix_overlap: dict[int, int] = {}

            for upstream_asn in upstream_asns:
                try:
                    upstream_ixlans = await self._peeringdb.get_network_ixlans(upstream_asn)
                    for ixlan in upstream_ixlans:
                        if ixlan.ix_id in current_ix_ids:
                            upstream_ix_overlap[ixlan.ix_id] = upstream_ix_overlap.get(ixlan.ix_id, 0) + 1
                except Exception:
                    continue

            return {
                "asn": asn,
                "name": presence.name,
                "current_ixes": [
                    {
                        "name": ix.name,
                        "country": ix.country,
                        "city": ix.city,
                        "members": ix.member_count,
                        "upstreams_present": upstream_ix_overlap.get(ix.id, 0),
                    }
                    for ix in presence.exchanges
                ],
                "ix_count": presence.ix_count,
                "facility_count": presence.facility_count,
                "total_upstreams_analyzed": len(upstream_asns),
            }

        except PeeringDBNotFoundError:
            return {"asn": asn, "error": "Not found in PeeringDB"}

    # ========================================================================
    # Peering Report
    # ========================================================================

    async def get_peering_report(self, asn: int) -> PeeringReport:
        """
        Generate comprehensive peering report.

        Args:
            asn: AS number

        Returns:
            PeeringReport with candidates and recommendations
        """
        report = PeeringReport(asn=asn)

        try:
            # Get basic info
            network = await self._peeringdb.get_network_by_asn(asn)
            report.name = network.name

            # Get current presence
            ixlans = await self._peeringdb.get_network_ixlans(asn)
            report.current_ix_count = len(set(c.ix_id for c in ixlans))

            # Count unique peers at IXes
            peer_asns: set[int] = set()
            for ix_id in set(c.ix_id for c in ixlans):
                try:
                    members = await self._peeringdb.get_ix_members(ix_id)
                    peer_asns.update(m.asn for m in members)
                except Exception:
                    continue
            peer_asns.discard(asn)
            report.current_peer_count = len(peer_asns)

            # Get candidates and recommendations in parallel
            candidates_task = self.find_peering_candidates(asn)
            ix_recs_task = self.recommend_ixes(asn)

            candidates, ix_recs = await asyncio.gather(
                candidates_task,
                ix_recs_task,
            )

            report.candidates = candidates
            report.ix_recommendations = ix_recs

            # Estimate traffic shift potential
            if report.candidates:
                # Rough estimate: each peer could shift some transit traffic
                report.estimated_traffic_shift = min(
                    len([c for c in candidates if c.score > 5]) * 5.0,
                    50.0,  # Cap at 50%
                )

        except PeeringDBNotFoundError:
            pass

        return report

    async def analyze_peering_opportunity(
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
            Detailed analysis of peering feasibility
        """
        try:
            opportunity = await self._peeringdb.find_peering_opportunities(asn1, asn2)

            # Get network details
            net1 = await self._peeringdb.get_network_by_asn(asn1)
            net2 = await self._peeringdb.get_network_by_asn(asn2)

            # Assess feasibility
            feasibility = "high"
            blockers = []

            if not opportunity.common_ixes and not opportunity.common_facilities:
                feasibility = "low"
                blockers.append("No common locations")

            if net2.policy_general.lower() == "restrictive":
                feasibility = "medium" if feasibility == "high" else feasibility
                blockers.append(f"{net2.name} has restrictive peering policy")

            if net1.policy_general.lower() == "restrictive":
                feasibility = "medium" if feasibility == "high" else feasibility
                blockers.append(f"{net1.name} has restrictive peering policy")

            return {
                "asn1": {
                    "asn": asn1,
                    "name": net1.name,
                    "policy": net1.policy_general,
                    "prefixes": net1.total_prefixes,
                },
                "asn2": {
                    "asn": asn2,
                    "name": net2.name,
                    "policy": net2.policy_general,
                    "prefixes": net2.total_prefixes,
                },
                "common_ixes": [
                    {
                        "name": cix.ix.name,
                        "country": cix.ix.country,
                        "can_peer": cix.can_peer,
                        "net1_speed": cix.net1_connection.speed_gbps,
                        "net2_speed": cix.net2_connection.speed_gbps,
                    }
                    for cix in opportunity.common_ixes
                ],
                "common_facilities": [
                    {"name": f.name, "city": f.city, "country": f.country}
                    for f in opportunity.common_facilities
                ],
                "opportunity_count": opportunity.opportunity_count,
                "feasibility": feasibility,
                "blockers": blockers,
                "recommendation": self._get_peering_recommendation(
                    opportunity, feasibility, blockers
                ),
            }

        except PeeringDBNotFoundError as e:
            return {"error": str(e)}

    def _get_peering_recommendation(
        self,
        opportunity: Any,
        feasibility: str,
        blockers: list[str],
    ) -> str:
        """Generate a peering recommendation."""
        if feasibility == "high" and opportunity.common_ixes:
            best_ix = opportunity.common_ixes[0].ix.name
            return f"Recommend establishing peering at {best_ix}"

        if feasibility == "medium":
            if opportunity.common_ixes:
                return "Peering possible but may require negotiation"
            return "Consider joining a common IX first"

        if not opportunity.common_ixes and opportunity.common_facilities:
            return "Private peering may be possible at common facilities"

        return "No immediate peering opportunity - consider IX expansion"
