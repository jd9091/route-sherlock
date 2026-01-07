"""
Path Analyzer.

Analyze BGP paths, detect anomalies, and measure latency using Atlas.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from route_sherlock.collectors.ripestat import RIPEstatClient
from route_sherlock.collectors.atlas import AtlasClient
from route_sherlock.models.atlas import MeasurementType

from route_sherlock.analysis.models import (
    Anomaly,
    AnomalyReport,
    AnomalyType,
    ASPath,
    LatencyAnalysis,
    LatencyMeasurement,
    PathAnalysis,
    PathHop,
    RiskLevel,
)


class PathAnalyzer:
    """
    Analyzer for BGP paths and routing behavior.

    Provides path analysis, anomaly detection, and latency measurement
    capabilities using RIPEstat and RIPE Atlas data.

    Example:
        async with PathAnalyzer() as analyzer:
            analysis = await analyzer.analyze_paths("8.8.8.0/24")
            print(f"Average path length: {analysis.avg_path_length}")
    """

    def __init__(
        self,
        ripestat: RIPEstatClient | None = None,
        atlas: AtlasClient | None = None,
    ):
        """
        Initialize analyzer with optional pre-configured clients.

        Args:
            ripestat: RIPEstat client instance
            atlas: Atlas client instance
        """
        self._ripestat = ripestat
        self._atlas = atlas
        self._owns_clients = False

    async def __aenter__(self) -> "PathAnalyzer":
        if not self._ripestat:
            self._ripestat = RIPEstatClient()
            await self._ripestat.__aenter__()
        if not self._atlas:
            self._atlas = AtlasClient()
            await self._atlas.__aenter__()
        self._owns_clients = True
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._owns_clients:
            if self._ripestat:
                await self._ripestat.__aexit__(exc_type, exc_val, exc_tb)
            if self._atlas:
                await self._atlas.__aexit__(exc_type, exc_val, exc_tb)

    # ========================================================================
    # Path Analysis
    # ========================================================================

    async def analyze_paths(self, resource: str) -> PathAnalysis:
        """
        Analyze BGP paths to a prefix or from an ASN.

        Args:
            resource: Prefix (e.g., "8.8.8.0/24") or ASN (e.g., "AS15169")

        Returns:
            PathAnalysis with path statistics
        """
        analysis = PathAnalysis(destination=resource)

        try:
            # Get looking glass data for current paths
            lg_data = await self._ripestat.get_looking_glass(resource)

            all_paths: list[list[int]] = []
            origin_asns: set[int] = set()

            for rrc in lg_data.rrcs:
                for peer in rrc.peers:
                    if peer.as_path:
                        path = self._parse_as_path(peer.as_path)
                        if path:
                            all_paths.append(path)
                            if path:
                                origin_asns.add(path[-1])

            if not all_paths:
                return analysis

            # Deduplicate paths
            unique_path_strs = set(tuple(p) for p in all_paths)
            unique_paths = [list(p) for p in unique_path_strs]

            # Calculate statistics
            path_lengths = [len(p) for p in unique_paths]
            analysis.path_count = len(all_paths)
            analysis.unique_paths = [
                self._create_as_path(p) for p in unique_paths[:20]
            ]
            analysis.avg_path_length = sum(path_lengths) / len(path_lengths)
            analysis.min_path_length = min(path_lengths)
            analysis.max_path_length = max(path_lengths)
            analysis.origin_asns = list(origin_asns)

            # Find common transit ASNs
            analysis.common_transit = self._find_common_transit(all_paths)

        except Exception:
            pass

        return analysis

    def _parse_as_path(self, path_str: str) -> list[int]:
        """Parse AS path string into list of ASNs."""
        asns = []
        for part in path_str.split():
            # Handle AS sets like {1234,5678}
            if part.startswith("{"):
                continue
            try:
                asns.append(int(part))
            except ValueError:
                continue
        return asns

    def _create_as_path(self, path: list[int]) -> ASPath:
        """Create ASPath object with analysis."""
        hops = []
        for i, asn in enumerate(path):
            hops.append(PathHop(
                asn=asn,
                position=i,
                is_origin=i == 0,
                is_destination=i == len(path) - 1,
            ))

        # Detect prepending
        has_prepending = False
        prepend_count = 0
        for i in range(1, len(path)):
            if path[i] == path[i - 1]:
                has_prepending = True
                prepend_count += 1

        return ASPath(
            path=path,
            hops=hops,
            length=len(path),
            origin_asn=path[-1] if path else 0,
            has_prepending=has_prepending,
            prepend_count=prepend_count,
        )

    def _find_common_transit(
        self,
        paths: list[list[int]],
        threshold: float = 0.5,
    ) -> list[int]:
        """Find ASNs that appear in most paths."""
        if not paths:
            return []

        # Count ASN appearances (excluding origin)
        asn_counts: Counter[int] = Counter()
        for path in paths:
            # Exclude first (observer) and last (origin) ASN
            transit_asns = set(path[1:-1]) if len(path) > 2 else set()
            asn_counts.update(transit_asns)

        # Return ASNs appearing in more than threshold of paths
        min_count = len(paths) * threshold
        common = [asn for asn, count in asn_counts.most_common(10) if count >= min_count]
        return common

    async def get_path_changes(
        self,
        resource: str,
        hours: int = 24,
    ) -> dict[str, Any]:
        """
        Detect path changes over a time period.

        Args:
            resource: Prefix or ASN
            hours: Number of hours to look back

        Returns:
            Dict with path change information
        """
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)

        try:
            updates = await self._ripestat.get_bgp_updates(
                resource,
                start_time=start_time,
                end_time=end_time,
            )

            announcements = 0
            withdrawals = 0
            path_changes: list[dict] = []

            for update in updates.updates:
                if update.type == "A":
                    announcements += 1
                elif update.type == "W":
                    withdrawals += 1

                if update.attrs and "as_path" in update.attrs:
                    path_changes.append({
                        "timestamp": update.timestamp,
                        "type": update.type,
                        "path": update.attrs.get("as_path"),
                    })

            return {
                "resource": resource,
                "period_hours": hours,
                "announcements": announcements,
                "withdrawals": withdrawals,
                "total_updates": len(updates.updates),
                "path_changes": path_changes[:50],
                "is_stable": len(updates.updates) < 10,
            }

        except Exception as e:
            return {
                "resource": resource,
                "error": str(e),
            }

    # ========================================================================
    # Anomaly Detection
    # ========================================================================

    async def detect_anomalies(self, resource: str) -> AnomalyReport:
        """
        Detect routing anomalies for a prefix or ASN.

        Args:
            resource: Prefix or ASN to check

        Returns:
            AnomalyReport with detected issues
        """
        report = AnomalyReport(resource=resource)
        anomalies: list[Anomaly] = []

        # Run checks in parallel
        moas_task = self._check_moas(resource)
        rpki_task = self._check_rpki(resource)
        path_task = self._check_unusual_paths(resource)

        moas_result, rpki_result, path_result = await asyncio.gather(
            moas_task,
            rpki_task,
            path_task,
            return_exceptions=True,
        )

        if isinstance(moas_result, list):
            anomalies.extend(moas_result)
        if isinstance(rpki_result, list):
            anomalies.extend(rpki_result)
        if isinstance(path_result, list):
            anomalies.extend(path_result)

        report.anomalies = anomalies

        # Set overall risk level
        if any(a.severity == RiskLevel.CRITICAL for a in anomalies):
            report.risk_level = RiskLevel.CRITICAL
        elif any(a.severity == RiskLevel.HIGH for a in anomalies):
            report.risk_level = RiskLevel.HIGH
        elif any(a.severity == RiskLevel.MEDIUM for a in anomalies):
            report.risk_level = RiskLevel.MEDIUM

        return report

    async def _check_moas(self, resource: str) -> list[Anomaly]:
        """Check for Multiple Origin AS (MOAS) conflicts."""
        anomalies = []

        try:
            analysis = await self.analyze_paths(resource)

            if len(analysis.origin_asns) > 1:
                anomalies.append(Anomaly(
                    type=AnomalyType.MOAS,
                    severity=RiskLevel.HIGH,
                    resource=resource,
                    description=f"Multiple origin ASNs detected: {analysis.origin_asns}",
                    details={
                        "origin_asns": analysis.origin_asns,
                        "path_count": analysis.path_count,
                    },
                ))
        except Exception:
            pass

        return anomalies

    async def _check_rpki(self, resource: str) -> list[Anomaly]:
        """Check for RPKI validation issues."""
        anomalies = []

        # Skip if resource is an ASN
        if resource.upper().startswith("AS") or resource.isdigit():
            return anomalies

        try:
            validation = await self._ripestat.get_rpki_validation(resource)

            if validation.status == "invalid":
                anomalies.append(Anomaly(
                    type=AnomalyType.RPKI_INVALID,
                    severity=RiskLevel.CRITICAL,
                    resource=resource,
                    description="RPKI validation failed - prefix may be hijacked",
                    expected_origin=validation.expected_origin,
                    observed_origin=validation.observed_origin,
                    details={
                        "status": validation.status,
                        "roas": validation.roas,
                    },
                ))
        except Exception:
            pass

        return anomalies

    async def _check_unusual_paths(self, resource: str) -> list[Anomaly]:
        """Check for unusual path characteristics."""
        anomalies = []

        try:
            analysis = await self.analyze_paths(resource)

            # Check for very long paths
            if analysis.max_path_length > 10:
                anomalies.append(Anomaly(
                    type=AnomalyType.UNUSUAL_PATH_LENGTH,
                    severity=RiskLevel.MEDIUM,
                    resource=resource,
                    description=f"Unusually long AS path detected ({analysis.max_path_length} hops)",
                    details={
                        "max_length": analysis.max_path_length,
                        "avg_length": analysis.avg_path_length,
                    },
                ))

            # Check for excessive prepending
            for path in analysis.unique_paths:
                if path.prepend_count > 5:
                    anomalies.append(Anomaly(
                        type=AnomalyType.UNUSUAL_PATH_LENGTH,
                        severity=RiskLevel.LOW,
                        resource=resource,
                        description=f"Excessive AS prepending detected ({path.prepend_count} prepends)",
                        details={
                            "path": path.path,
                            "prepend_count": path.prepend_count,
                        },
                    ))
                    break  # Only report once

        except Exception:
            pass

        return anomalies

    # ========================================================================
    # Latency Analysis
    # ========================================================================

    async def measure_latency(
        self,
        target: str,
        source_asn: int | None = None,
        source_country: str | None = None,
        probe_count: int = 10,
    ) -> LatencyAnalysis:
        """
        Measure latency to a target using Atlas probes.

        Args:
            target: Target IP or hostname
            source_asn: Limit probes to specific ASN
            source_country: Limit probes to specific country
            probe_count: Number of probes to use

        Returns:
            LatencyAnalysis with measurements
        """
        analysis = LatencyAnalysis(target=target)
        measurements: list[LatencyMeasurement] = []

        try:
            # Find existing ping measurements to target
            ping_measurements = await self._atlas.get_builtin_measurements_for_target(
                target,
                MeasurementType.PING,
            )

            if not ping_measurements:
                return analysis

            measurement = ping_measurements[0]

            # Get probes based on filters
            if source_asn:
                probes = await self._atlas.get_probes_by_asn(source_asn)
            elif source_country:
                probes = await self._atlas.get_probes_by_country(source_country)
            else:
                # Get diverse set of probes
                probes = (await self._atlas.get_probes(limit=probe_count * 2)).probes

            probe_ids = [p.id for p in probes[:probe_count]]

            if not probe_ids:
                return analysis

            # Get results
            results = await self._atlas.get_latest_results(
                measurement.id,
                probe_ids=probe_ids,
            )

            for result in results.get_ping_results():
                probe = next((p for p in probes if p.id == result.probe_id), None)

                measurements.append(LatencyMeasurement(
                    source_probe_id=result.probe_id,
                    source_asn=probe.asn if probe else None,
                    source_country=probe.country_code if probe else "",
                    target=target,
                    min_rtt=result.min_rtt,
                    avg_rtt=result.avg_rtt,
                    max_rtt=result.max_rtt,
                    packet_loss=result.packet_loss,
                    timestamp=datetime.fromtimestamp(result.timestamp) if result.timestamp else None,
                ))

            analysis.measurements = measurements
            analysis.measurement_count = len(measurements)

            # Calculate aggregates
            valid_rtts = [m.avg_rtt for m in measurements if m.avg_rtt is not None]
            if valid_rtts:
                analysis.global_avg_rtt = sum(valid_rtts) / len(valid_rtts)

            # Group by country
            by_country: dict[str, list[float]] = {}
            for m in measurements:
                if m.source_country and m.avg_rtt is not None:
                    by_country.setdefault(m.source_country, []).append(m.avg_rtt)

            analysis.by_country = {
                country: sum(rtts) / len(rtts)
                for country, rtts in by_country.items()
            }

            # Group by ASN
            by_asn: dict[int, list[float]] = {}
            for m in measurements:
                if m.source_asn and m.avg_rtt is not None:
                    by_asn.setdefault(m.source_asn, []).append(m.avg_rtt)

            analysis.by_asn = {
                asn: sum(rtts) / len(rtts)
                for asn, rtts in by_asn.items()
            }

        except Exception:
            pass

        return analysis

    async def compare_latency(
        self,
        target1: str,
        target2: str,
        source_country: str | None = None,
    ) -> dict[str, Any]:
        """
        Compare latency to two targets.

        Args:
            target1: First target
            target2: Second target
            source_country: Country to measure from

        Returns:
            Comparison dict
        """
        lat1, lat2 = await asyncio.gather(
            self.measure_latency(target1, source_country=source_country),
            self.measure_latency(target2, source_country=source_country),
        )

        return {
            "target1": {
                "target": target1,
                "avg_rtt": lat1.global_avg_rtt,
                "measurement_count": lat1.measurement_count,
            },
            "target2": {
                "target": target2,
                "avg_rtt": lat2.global_avg_rtt,
                "measurement_count": lat2.measurement_count,
            },
            "comparison": {
                "faster": target1 if (lat1.global_avg_rtt or float("inf")) < (lat2.global_avg_rtt or float("inf")) else target2,
                "difference_ms": abs((lat1.global_avg_rtt or 0) - (lat2.global_avg_rtt or 0)),
            },
        }
