"""
RIPE Atlas API Client.

Async client for querying RIPE Atlas measurement network.
Documentation: https://atlas.ripe.net/docs/apis/

Usage:
    async with AtlasClient(api_key="your-key") as client:
        probes = await client.get_probes_by_asn(16509)
        for probe in probes:
            print(f"Probe {probe.id}: {probe.country_code}")
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

import httpx

from route_sherlock.models.atlas import (
    Anchor,
    AnchorList,
    BuiltinMeasurement,
    MeasurementDefinition,
    MeasurementResults,
    MeasurementType,
    Probe,
    ProbeList,
)
from route_sherlock.cache.store import Cache


class AtlasError(Exception):
    """Base exception for RIPE Atlas API errors."""
    pass


class AtlasAuthError(AtlasError):
    """Raised when authentication fails."""
    pass


class AtlasRateLimitError(AtlasError):
    """Raised when rate limit is exceeded."""
    pass


class AtlasNotFoundError(AtlasError):
    """Raised when a resource is not found."""
    pass


class AtlasClient:
    """
    Async client for RIPE Atlas API.

    API access requires an account. Some endpoints require an API key.
    Rate limits vary by endpoint and authentication level.

    Example:
        async with AtlasClient(api_key="your-key") as client:
            # Get probes for an ASN
            probes = await client.get_probes_by_asn(16509)

            # Get measurement results
            results = await client.get_measurement_results(1001)
    """

    BASE_URL = "https://atlas.ripe.net/api/v2"

    def __init__(
        self,
        api_key: str | None = None,
        cache: Cache | None = None,
        cache_ttl: int = 300,  # 5 minutes default
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        """
        Initialize Atlas client.

        Args:
            api_key: RIPE Atlas API key (required for some endpoints)
            cache: Optional cache instance for response caching
            cache_ttl: Cache time-to-live in seconds
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts for failed requests
        """
        self.api_key = api_key
        self.cache = cache
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self.max_retries = max_retries
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "AtlasClient":
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Key {self.api_key}"

        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            headers=headers,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._client:
            await self._client.aclose()

    # ========================================================================
    # Core Request Methods
    # ========================================================================

    async def _request(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        use_cache: bool = True,
    ) -> dict[str, Any] | list[Any]:
        """
        Make a request to RIPE Atlas API.

        Args:
            endpoint: API endpoint path (e.g., '/probes')
            params: Query parameters
            use_cache: Whether to use cached response if available

        Returns:
            Parsed JSON response
        """
        if not self._client:
            raise AtlasError("Client not initialized. Use 'async with' context manager.")

        params = params or {}

        # Build cache key
        cache_key = f"atlas:{endpoint}:{urlencode(sorted(params.items()))}"

        # Check cache
        if use_cache and self.cache:
            cached = await self.cache.get(cache_key)
            if cached is not None:
                return cached

        # Build URL
        url = f"{self.BASE_URL}{endpoint}"

        # Make request with retries
        last_error: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                response = await self._client.get(url, params=params)

                if response.status_code == 401:
                    raise AtlasAuthError("Authentication failed. Check your API key.")
                if response.status_code == 403:
                    raise AtlasAuthError("Access denied. Insufficient permissions.")
                if response.status_code == 404:
                    raise AtlasNotFoundError(f"Resource not found: {endpoint}")
                if response.status_code == 429:
                    raise AtlasRateLimitError("Rate limit exceeded")

                response.raise_for_status()
                data = response.json()

                # Cache successful response
                if self.cache:
                    await self.cache.set(cache_key, data, ttl=self.cache_ttl)

                return data

            except httpx.HTTPStatusError as e:
                last_error = e
                if e.response.status_code in (401, 403, 404):
                    raise
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)

            except httpx.RequestError as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)

        raise AtlasError(f"Request failed after {self.max_retries} attempts: {last_error}")

    async def _paginate(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        max_pages: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Fetch all pages from a paginated endpoint.

        Args:
            endpoint: API endpoint
            params: Query parameters
            max_pages: Maximum number of pages to fetch

        Returns:
            Combined list of all results
        """
        params = params or {}
        all_results = []
        page = 1

        while page <= max_pages:
            params["page"] = page
            data = await self._request(endpoint, params, use_cache=False)

            if isinstance(data, dict):
                results = data.get("results", [])
                all_results.extend(results)

                if not data.get("next"):
                    break
            else:
                all_results.extend(data)
                break

            page += 1

        return all_results

    @staticmethod
    def _format_time(dt: datetime) -> int:
        """Convert datetime to Unix timestamp."""
        return int(dt.timestamp())

    # ========================================================================
    # Probe Endpoints
    # ========================================================================

    async def get_probe(self, probe_id: int) -> Probe:
        """
        Get details for a specific probe.

        Args:
            probe_id: Probe ID

        Returns:
            Probe details
        """
        data = await self._request(f"/probes/{probe_id}/")
        return Probe(**data)

    async def get_probes(
        self,
        asn: int | None = None,
        asn_v4: int | None = None,
        asn_v6: int | None = None,
        country_code: str | None = None,
        prefix: str | None = None,
        is_anchor: bool | None = None,
        status: int | None = None,
        tags: list[str] | None = None,
        limit: int = 100,
    ) -> ProbeList:
        """
        Search for probes with filters.

        Args:
            asn: Filter by ASN (either v4 or v6)
            asn_v4: Filter by IPv4 ASN
            asn_v6: Filter by IPv6 ASN
            country_code: Filter by country (ISO 2-letter)
            prefix: Filter by prefix
            is_anchor: Filter anchors only
            status: Filter by status (1=connected, 2=disconnected, 3=abandoned)
            tags: Filter by tags
            limit: Maximum results per page

        Returns:
            ProbeList with matching probes
        """
        params: dict[str, Any] = {"page_size": min(limit, 500)}

        if asn is not None:
            params["asn"] = asn
        if asn_v4 is not None:
            params["asn_v4"] = asn_v4
        if asn_v6 is not None:
            params["asn_v6"] = asn_v6
        if country_code is not None:
            params["country_code"] = country_code.upper()
        if prefix is not None:
            params["prefix"] = prefix
        if is_anchor is not None:
            params["is_anchor"] = str(is_anchor).lower()
        if status is not None:
            params["status"] = status
        if tags:
            params["tags"] = ",".join(tags)

        data = await self._request("/probes/", params)

        probes = [Probe(**p) for p in data.get("results", [])]
        return ProbeList(
            count=data.get("count", len(probes)),
            next=data.get("next"),
            previous=data.get("previous"),
            probes=probes,
        )

    async def get_probes_by_asn(
        self,
        asn: int,
        connected_only: bool = True,
        include_anchors: bool = True,
    ) -> list[Probe]:
        """
        Get all probes for an ASN.

        Args:
            asn: AS number
            connected_only: Only return connected probes
            include_anchors: Include anchor probes

        Returns:
            List of probes in the ASN
        """
        params: dict[str, Any] = {"asn": asn, "page_size": 500}
        if connected_only:
            params["status"] = 1  # Connected

        all_probes = await self._paginate("/probes/", params)
        probes = [Probe(**p) for p in all_probes]

        if not include_anchors:
            probes = [p for p in probes if not p.is_anchor]

        return probes

    async def get_probes_by_country(
        self,
        country_code: str,
        connected_only: bool = True,
    ) -> list[Probe]:
        """
        Get all probes in a country.

        Args:
            country_code: ISO 2-letter country code
            connected_only: Only return connected probes

        Returns:
            List of probes in the country
        """
        params: dict[str, Any] = {
            "country_code": country_code.upper(),
            "page_size": 500,
        }
        if connected_only:
            params["status"] = 1

        all_probes = await self._paginate("/probes/", params)
        return [Probe(**p) for p in all_probes]

    # ========================================================================
    # Anchor Endpoints
    # ========================================================================

    async def get_anchor(self, anchor_id: int) -> Anchor:
        """
        Get details for a specific anchor.

        Args:
            anchor_id: Anchor ID

        Returns:
            Anchor details
        """
        data = await self._request(f"/anchors/{anchor_id}/")
        return Anchor(**data)

    async def get_anchors(
        self,
        country_code: str | None = None,
        asn_v4: int | None = None,
        asn_v6: int | None = None,
        search: str | None = None,
        limit: int = 100,
    ) -> AnchorList:
        """
        Search for anchors.

        Args:
            country_code: Filter by country
            asn_v4: Filter by IPv4 ASN
            asn_v6: Filter by IPv6 ASN
            search: Text search
            limit: Maximum results

        Returns:
            AnchorList with matching anchors
        """
        params: dict[str, Any] = {"page_size": min(limit, 500)}

        if country_code:
            params["country"] = country_code.upper()
        if asn_v4 is not None:
            params["as_v4"] = asn_v4
        if asn_v6 is not None:
            params["as_v6"] = asn_v6
        if search:
            params["search"] = search

        data = await self._request("/anchors/", params)

        anchors = [Anchor(**a) for a in data.get("results", [])]
        return AnchorList(
            count=data.get("count", len(anchors)),
            next=data.get("next"),
            previous=data.get("previous"),
            anchors=anchors,
        )

    async def get_anchor_by_asn(self, asn: int) -> list[Anchor]:
        """
        Get all anchors for an ASN.

        Args:
            asn: AS number

        Returns:
            List of anchors in the ASN
        """
        params: dict[str, Any] = {"as_v4": asn, "page_size": 500}
        all_anchors = await self._paginate("/anchors/", params)

        # Also check v6
        params_v6: dict[str, Any] = {"as_v6": asn, "page_size": 500}
        v6_anchors = await self._paginate("/anchors/", params_v6)

        # Combine and dedupe
        seen_ids = set()
        combined = []
        for a in all_anchors + v6_anchors:
            if a["id"] not in seen_ids:
                seen_ids.add(a["id"])
                combined.append(Anchor(**a))

        return combined

    # ========================================================================
    # Measurement Endpoints
    # ========================================================================

    async def get_measurement(self, measurement_id: int) -> MeasurementDefinition:
        """
        Get measurement definition.

        Args:
            measurement_id: Measurement ID

        Returns:
            MeasurementDefinition with configuration
        """
        data = await self._request(f"/measurements/{measurement_id}/")
        return MeasurementDefinition(**data)

    async def get_measurement_results(
        self,
        measurement_id: int,
        start: datetime | None = None,
        stop: datetime | None = None,
        probe_ids: list[int] | None = None,
        limit: int = 1000,
    ) -> MeasurementResults:
        """
        Get results from a measurement.

        Args:
            measurement_id: Measurement ID
            start: Start time (Unix timestamp or datetime)
            stop: Stop time
            probe_ids: Filter by specific probe IDs
            limit: Maximum results

        Returns:
            MeasurementResults with raw result data
        """
        params: dict[str, Any] = {}

        if start:
            params["start"] = self._format_time(start)
        if stop:
            params["stop"] = self._format_time(stop)
        if probe_ids:
            params["probe_ids"] = ",".join(str(p) for p in probe_ids)

        # Results endpoint returns list directly
        data = await self._request(
            f"/measurements/{measurement_id}/results/",
            params,
            use_cache=False,  # Results change frequently
        )

        results = data if isinstance(data, list) else data.get("results", [])
        results = results[:limit]

        # Get measurement type
        measurement = await self.get_measurement(measurement_id)

        return MeasurementResults(
            measurement_id=measurement_id,
            type=measurement.type,
            results=results,
        )

    async def get_latest_results(
        self,
        measurement_id: int,
        probe_ids: list[int] | None = None,
    ) -> MeasurementResults:
        """
        Get the latest results from a measurement.

        Args:
            measurement_id: Measurement ID
            probe_ids: Filter by specific probe IDs

        Returns:
            MeasurementResults with latest data
        """
        params: dict[str, Any] = {}
        if probe_ids:
            params["probe_ids"] = ",".join(str(p) for p in probe_ids)

        data = await self._request(
            f"/measurements/{measurement_id}/latest/",
            params,
            use_cache=False,
        )

        results = data if isinstance(data, list) else data.get("results", [])
        measurement = await self.get_measurement(measurement_id)

        return MeasurementResults(
            measurement_id=measurement_id,
            type=measurement.type,
            results=results,
        )

    # ========================================================================
    # Built-in Anchor Measurements
    # ========================================================================

    async def get_anchor_measurements(
        self,
        anchor_id: int,
    ) -> list[BuiltinMeasurement]:
        """
        Get built-in measurements for an anchor.

        Each anchor has automatic ping/traceroute/dns measurements
        from all other anchors.

        Args:
            anchor_id: Anchor ID

        Returns:
            List of built-in measurements
        """
        data = await self._request(f"/anchors/{anchor_id}/measurements/")

        measurements = []
        for m in data.get("results", data if isinstance(data, list) else []):
            measurements.append(BuiltinMeasurement(
                measurement_id=m.get("id", m.get("measurement_id")),
                type=MeasurementType(m.get("type", "ping")),
                target=m.get("target", ""),
                target_ip=m.get("target_ip"),
                af=m.get("af", 4),
                description=m.get("description"),
            ))

        return measurements

    async def get_builtin_measurements_for_target(
        self,
        target: str,
        measurement_type: MeasurementType = MeasurementType.PING,
    ) -> list[MeasurementDefinition]:
        """
        Find built-in measurements targeting a specific host.

        Args:
            target: Target hostname or IP
            measurement_type: Type of measurement

        Returns:
            List of matching measurements
        """
        params: dict[str, Any] = {
            "target": target,
            "type": measurement_type.value,
            "is_oneoff": "false",
            "status": 2,  # Ongoing
            "page_size": 100,
        }

        data = await self._request("/measurements/", params)
        return [MeasurementDefinition(**m) for m in data.get("results", [])]

    # ========================================================================
    # Convenience Methods
    # ========================================================================

    async def get_probe_count_by_asn(self, asn: int) -> dict[str, int]:
        """
        Get count of probes for an ASN by status.

        Args:
            asn: AS number

        Returns:
            Dict with 'connected', 'total', 'anchors' counts
        """
        # Get all probes
        all_probes = await self.get_probes_by_asn(asn, connected_only=False)

        connected = sum(1 for p in all_probes if p.is_connected)
        anchors = sum(1 for p in all_probes if p.is_anchor)

        return {
            "total": len(all_probes),
            "connected": connected,
            "anchors": anchors,
        }

    async def get_asn_coverage(self, asn: int) -> dict[str, Any]:
        """
        Get Atlas coverage information for an ASN.

        Args:
            asn: AS number

        Returns:
            Dict with probes, anchors, and coverage details
        """
        probes = await self.get_probes_by_asn(asn, connected_only=False)
        anchors = await self.get_anchor_by_asn(asn)

        countries = set(p.country_code for p in probes if p.country_code)

        return {
            "asn": asn,
            "probe_count": len(probes),
            "connected_probes": sum(1 for p in probes if p.is_connected),
            "anchor_count": len(anchors),
            "countries": sorted(countries),
            "probes": probes,
            "anchors": anchors,
        }

    async def ping_from_asn(
        self,
        target: str,
        source_asn: int,
        probe_count: int = 5,
    ) -> MeasurementResults | None:
        """
        Find existing ping measurements to a target from probes in an ASN.

        Note: This searches for existing measurements, not creating new ones.
        Creating measurements requires API key with credits.

        Args:
            target: Target to ping
            source_asn: ASN to find probes in
            probe_count: Number of probes to use

        Returns:
            Results if found, None otherwise
        """
        # Find measurements to this target
        measurements = await self.get_builtin_measurements_for_target(
            target,
            MeasurementType.PING,
        )

        if not measurements:
            return None

        # Get probes in the ASN
        probes = await self.get_probes_by_asn(source_asn, connected_only=True)
        probe_ids = [p.id for p in probes[:probe_count]]

        if not probe_ids:
            return None

        # Get results from first matching measurement
        return await self.get_latest_results(
            measurements[0].id,
            probe_ids=probe_ids,
        )


# ============================================================================
# Synchronous Wrapper
# ============================================================================

class AtlasClientSync:
    """
    Synchronous wrapper around AtlasClient.

    Useful for CLI and simple scripts.

    Example:
        client = AtlasClientSync(api_key="your-key")
        probes = client.get_probes_by_asn(16509)
    """

    def __init__(self, **kwargs):
        self._kwargs = kwargs

    def get_probe(self, probe_id: int) -> Probe:
        async def _inner():
            async with AtlasClient(**self._kwargs) as client:
                return await client.get_probe(probe_id)
        return asyncio.run(_inner())

    def get_probes_by_asn(
        self,
        asn: int,
        connected_only: bool = True,
    ) -> list[Probe]:
        async def _inner():
            async with AtlasClient(**self._kwargs) as client:
                return await client.get_probes_by_asn(asn, connected_only)
        return asyncio.run(_inner())

    def get_probes_by_country(
        self,
        country_code: str,
        connected_only: bool = True,
    ) -> list[Probe]:
        async def _inner():
            async with AtlasClient(**self._kwargs) as client:
                return await client.get_probes_by_country(country_code, connected_only)
        return asyncio.run(_inner())

    def get_anchor_by_asn(self, asn: int) -> list[Anchor]:
        async def _inner():
            async with AtlasClient(**self._kwargs) as client:
                return await client.get_anchor_by_asn(asn)
        return asyncio.run(_inner())

    def get_measurement_results(
        self,
        measurement_id: int,
        start: datetime | None = None,
        stop: datetime | None = None,
    ) -> MeasurementResults:
        async def _inner():
            async with AtlasClient(**self._kwargs) as client:
                return await client.get_measurement_results(measurement_id, start, stop)
        return asyncio.run(_inner())

    def get_anchor_measurements(self, anchor_id: int) -> list[BuiltinMeasurement]:
        async def _inner():
            async with AtlasClient(**self._kwargs) as client:
                return await client.get_anchor_measurements(anchor_id)
        return asyncio.run(_inner())

    def get_asn_coverage(self, asn: int) -> dict[str, Any]:
        async def _inner():
            async with AtlasClient(**self._kwargs) as client:
                return await client.get_asn_coverage(asn)
        return asyncio.run(_inner())
