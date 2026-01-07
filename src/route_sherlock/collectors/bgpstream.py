"""
BGPStream Collector.

Provides access to historical BGP data from RouteViews and RIPE RIS.
Enables backtesting against real incidents.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class BGPEvent:
    """A single BGP update event."""
    timestamp: datetime
    event_type: str  # 'A' (announce), 'W' (withdraw)
    prefix: str
    as_path: list[int]
    origin_asn: int | None
    collector: str
    peer_asn: int | None = None

    @property
    def is_announcement(self) -> bool:
        return self.event_type == "A"

    @property
    def is_withdrawal(self) -> bool:
        return self.event_type == "W"


@dataclass
class AnomalyDetection:
    """Detected anomaly in BGP data."""
    anomaly_type: str  # 'hijack', 'leak', 'more_specific', 'origin_change'
    timestamp: datetime
    prefix: str
    description: str
    evidence: dict = field(default_factory=dict)
    severity: str = "medium"  # low, medium, high, critical


class BGPStreamClient:
    """
    Client for accessing historical BGP data via BGPStream.

    Provides access to RouteViews and RIPE RIS collector archives.

    Example:
        client = BGPStreamClient()
        events = client.get_updates(
            prefix="1.1.1.0/24",
            start_time=datetime(2024, 6, 27, 18, 0),
            end_time=datetime(2024, 6, 27, 21, 0),
        )
        for event in events:
            print(f"{event.timestamp} | {event.prefix} | {event.as_path}")
    """

    # Use fewer collectors for faster queries
    DEFAULT_COLLECTORS = [
        "route-views2",
        "route-views.linx",
    ]

    ALL_COLLECTORS = [
        "route-views2",
        "route-views.linx",
        "route-views.saopaulo",
        "rrc00",
        "rrc01",
        "rrc03",
    ]

    def __init__(self, collectors: list[str] | None = None):
        """
        Initialize BGPStream client.

        Args:
            collectors: List of collectors to query (default: major collectors)
        """
        self.collectors = collectors or self.DEFAULT_COLLECTORS
        self._stream = None

    def get_updates(
        self,
        start_time: datetime,
        end_time: datetime,
        prefix: str | None = None,
        origin_asn: int | None = None,
        collectors: list[str] | None = None,
    ) -> Iterator[BGPEvent]:
        """
        Get BGP updates for a time range.

        Args:
            start_time: Start of query window
            end_time: End of query window
            prefix: Filter by prefix (e.g., "1.1.1.0/24")
            origin_asn: Filter by origin AS
            collectors: Override default collectors

        Yields:
            BGPEvent objects
        """
        try:
            import pybgpstream
        except ImportError:
            raise ImportError(
                "pybgpstream required for historical data. "
                "Install with: brew install bgpstream && pip install pybgpstream"
            )

        stream = pybgpstream.BGPStream(
            from_time=start_time.strftime("%Y-%m-%d %H:%M:%S"),
            until_time=end_time.strftime("%Y-%m-%d %H:%M:%S"),
            collectors=collectors or self.collectors,
            record_type="updates",
        )

        for rec in stream.records():
            for elem in rec:
                event_prefix = elem.fields.get("prefix", "")
                as_path_str = elem.fields.get("as-path", "")

                # Parse AS path
                as_path = []
                if as_path_str:
                    try:
                        as_path = [int(asn) for asn in as_path_str.split()]
                    except ValueError:
                        pass

                origin = as_path[-1] if as_path else None

                # Apply filters
                if prefix and not event_prefix.startswith(prefix.split("/")[0]):
                    continue
                if origin_asn and origin != origin_asn:
                    continue

                yield BGPEvent(
                    timestamp=datetime.utcfromtimestamp(elem.time),
                    event_type=elem.type,
                    prefix=event_prefix,
                    as_path=as_path,
                    origin_asn=origin,
                    collector=rec.collector,
                    peer_asn=elem.peer_asn,
                )

    def detect_anomalies(
        self,
        events: list[BGPEvent],
        expected_origin: int | None = None,
        expected_prefix: str | None = None,
    ) -> list[AnomalyDetection]:
        """
        Analyze events for anomalies.

        Args:
            events: List of BGP events to analyze
            expected_origin: Expected origin AS for the prefix
            expected_prefix: The prefix being monitored

        Returns:
            List of detected anomalies
        """
        anomalies = []
        seen_origins = set()
        seen_paths = {}
        baseline_paths = set()  # Track normal paths
        suspicious_ases_seen = set()  # Avoid duplicate alerts

        # First pass: establish baseline paths
        for event in events:
            if event.is_announcement and event.as_path:
                path_tuple = tuple(event.as_path)
                if len(event.as_path) <= 3:  # Short paths are likely normal
                    baseline_paths.add(path_tuple)

        for event in events:
            if not event.is_announcement:
                continue

            origin = event.origin_asn
            prefix = event.prefix
            path_tuple = tuple(event.as_path)

            # More specific prefix (potential hijack)
            if expected_prefix:
                expected_len = int(expected_prefix.split("/")[1])
                actual_len = int(prefix.split("/")[1]) if "/" in prefix else 32
                if actual_len > expected_len and prefix.startswith(expected_prefix.split("/")[0]):
                    anomalies.append(AnomalyDetection(
                        anomaly_type="more_specific",
                        timestamp=event.timestamp,
                        prefix=prefix,
                        description=f"More specific prefix {prefix} announced (expected {expected_prefix})",
                        evidence={"as_path": event.as_path, "origin": origin},
                        severity="critical",
                    ))

            # Unexpected origin (potential hijack)
            if expected_origin and origin and origin != expected_origin:
                # Check if this is a leak (expected origin still in path)
                if expected_origin in event.as_path:
                    anomalies.append(AnomalyDetection(
                        anomaly_type="leak",
                        timestamp=event.timestamp,
                        prefix=prefix,
                        description=f"Route leak: AS{origin} announcing, expected origin AS{expected_origin} in path",
                        evidence={"as_path": event.as_path, "leaker": origin},
                        severity="high",
                    ))
                else:
                    anomalies.append(AnomalyDetection(
                        anomaly_type="hijack",
                        timestamp=event.timestamp,
                        prefix=prefix,
                        description=f"Origin mismatch: AS{origin} instead of AS{expected_origin}",
                        evidence={"as_path": event.as_path, "expected": expected_origin, "actual": origin},
                        severity="critical",
                    ))

            # Path-based leak detection: origin is correct but path has unexpected ASes
            if expected_origin and origin == expected_origin and len(event.as_path) > 2:
                # Check for ASes between the expected path endpoints
                intermediate_ases = set(event.as_path[1:-1])  # ASes between first hop and origin

                # Compare against baseline - if path has extra ASes, it might be a leak
                for baseline in baseline_paths:
                    if len(baseline) <= 2 and event.as_path[0] == baseline[0] and event.as_path[-1] == baseline[-1]:
                        # Same endpoints but longer path - potential leak
                        extra_ases = intermediate_ases
                        for asn in extra_ases:
                            if asn not in suspicious_ases_seen:
                                suspicious_ases_seen.add(asn)
                                anomalies.append(AnomalyDetection(
                                    anomaly_type="path_leak",
                                    timestamp=event.timestamp,
                                    prefix=prefix,
                                    description=f"Path leak: AS{asn} injected into path (normal: {len(baseline)} hops, observed: {len(event.as_path)} hops)",
                                    evidence={
                                        "as_path": event.as_path,
                                        "baseline_path": list(baseline),
                                        "suspicious_as": asn,
                                    },
                                    severity="high",
                                ))
                        break

            # Track for origin changes
            if prefix not in seen_paths:
                seen_paths[prefix] = {}
            if origin:
                seen_origins.add(origin)
                if origin not in seen_paths[prefix]:
                    seen_paths[prefix][origin] = event.timestamp

        # Multiple origins for same prefix
        if len(seen_origins) > 1 and expected_origin:
            unexpected = seen_origins - {expected_origin}
            for asn in unexpected:
                anomalies.append(AnomalyDetection(
                    anomaly_type="origin_change",
                    timestamp=events[0].timestamp if events else datetime.utcnow(),
                    prefix=expected_prefix or "unknown",
                    description=f"Multiple origins detected: {seen_origins}",
                    evidence={"origins": list(seen_origins)},
                    severity="high",
                ))

        return anomalies

    def investigate_incident(
        self,
        prefix: str,
        expected_origin: int,
        start_time: datetime,
        end_time: datetime,
        collectors: list[str] | None = None,
    ) -> dict:
        """
        Investigate a potential BGP incident.

        Args:
            prefix: Prefix to investigate (e.g., "1.1.1.0/24")
            expected_origin: Expected origin AS
            start_time: Start of investigation window
            end_time: End of investigation window
            collectors: Collectors to query

        Returns:
            Investigation report dict
        """
        prefix_base = prefix.split("/")[0]
        prefix_network = ".".join(prefix_base.split(".")[:3]) + "."  # e.g., "1.1.1."

        # Collect events
        events = list(self.get_updates(
            start_time=start_time,
            end_time=end_time,
            collectors=collectors,
        ))

        # Filter to relevant prefixes (exact /24 network or more specific)
        relevant_events = [
            e for e in events
            if e.prefix.startswith(prefix_network) or e.prefix == prefix
        ]

        # Detect anomalies
        anomalies = self.detect_anomalies(
            relevant_events,
            expected_origin=expected_origin,
            expected_prefix=prefix,
        )

        # Build timeline
        timeline = {}
        for event in relevant_events:
            minute = event.timestamp.replace(second=0, microsecond=0)
            if minute not in timeline:
                timeline[minute] = {"announcements": 0, "withdrawals": 0, "anomalies": 0}
            if event.is_announcement:
                timeline[minute]["announcements"] += 1
            else:
                timeline[minute]["withdrawals"] += 1

        for anomaly in anomalies:
            minute = anomaly.timestamp.replace(second=0, microsecond=0)
            if minute in timeline:
                timeline[minute]["anomalies"] += 1

        # Find involved ASes
        involved_ases = set()
        for anomaly in anomalies:
            if "as_path" in anomaly.evidence:
                involved_ases.update(anomaly.evidence["as_path"])
            if "leaker" in anomaly.evidence:
                involved_ases.add(anomaly.evidence["leaker"])
        involved_ases.discard(expected_origin)

        return {
            "prefix": prefix,
            "expected_origin": expected_origin,
            "timeframe": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "duration_hours": (end_time - start_time).total_seconds() / 3600,
            },
            "total_events": len(relevant_events),
            "announcements": sum(1 for e in relevant_events if e.is_announcement),
            "withdrawals": sum(1 for e in relevant_events if e.is_withdrawal),
            "anomalies": [
                {
                    "type": a.anomaly_type,
                    "time": a.timestamp.isoformat(),
                    "prefix": a.prefix,
                    "description": a.description,
                    "severity": a.severity,
                    "evidence": a.evidence,
                }
                for a in anomalies
            ],
            "involved_ases": list(involved_ases),
            "timeline": {
                k.isoformat(): v for k, v in sorted(timeline.items())
            },
            "first_anomaly": anomalies[0].timestamp.isoformat() if anomalies else None,
            "collectors_queried": collectors or self.collectors,
        }
