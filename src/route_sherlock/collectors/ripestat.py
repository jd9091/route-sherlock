"""
RIPEstat API Client.

Async client for querying RIPEstat Data API endpoints.
Documentation: https://stat.ripe.net/docs/02.data-api/

Usage:
    async with RIPEstatClient() as client:
        status = await client.get_routing_status("AS16509")
        print(status.observed_neighbours)
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import httpx

from route_sherlock.models.ripestat import (
    AnnouncedPrefixes,
    ASNeighbours,
    ASOverview,
    ASPathLength,
    BGPUpdates,
    LookingGlass,
    RIPEstatResponse,
    RoutingHistory,
    RoutingStatus,
    RPKIValidation,
)
from route_sherlock.cache.store import Cache


class RIPEstatError(Exception):
    """Base exception for RIPEstat API errors."""
    pass


class RIPEstatRateLimitError(RIPEstatError):
    """Raised when rate limit is exceeded."""
    pass


class RIPEstatClient:
    """
    Async client for RIPEstat Data API.
    
    Rate limits: ~1000 requests/day without API key
    
    Example:
        async with RIPEstatClient() as client:
            # Get current routing status
            status = await client.get_routing_status("AS16509")
            
            # Get historical routing data
            history = await client.get_routing_history(
                "AS16509",
                start_time=datetime(2025, 1, 1),
                end_time=datetime(2025, 1, 2)
            )
    """
    
    BASE_URL = "https://stat.ripe.net/data"
    
    def __init__(
        self,
        cache: Cache | None = None,
        cache_ttl: int = 3600,  # 1 hour default
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        """
        Initialize RIPEstat client.
        
        Args:
            cache: Optional cache instance for response caching
            cache_ttl: Cache time-to-live in seconds
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts for failed requests
        """
        self.cache = cache
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self.max_retries = max_retries
        self._client: httpx.AsyncClient | None = None
    
    async def __aenter__(self) -> "RIPEstatClient":
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            headers={"Accept": "application/json"},
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
        params: dict[str, Any],
        use_cache: bool = True,
    ) -> dict[str, Any]:
        """
        Make a request to RIPEstat API.
        
        Args:
            endpoint: API endpoint name (e.g., 'routing-status')
            params: Query parameters
            use_cache: Whether to use cached response if available
            
        Returns:
            Parsed JSON response data
        """
        if not self._client:
            raise RIPEstatError("Client not initialized. Use 'async with' context manager.")
        
        # Build cache key
        cache_key = f"ripestat:{endpoint}:{urlencode(sorted(params.items()))}"
        
        # Check cache
        if use_cache and self.cache:
            cached = await self.cache.get(cache_key)
            if cached is not None:
                return cached
        
        # Build URL
        url = f"{self.BASE_URL}/{endpoint}/data.json"
        
        # Make request with retries
        last_error: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                response = await self._client.get(url, params=params)
                
                if response.status_code == 429:
                    raise RIPEstatRateLimitError("Rate limit exceeded")
                
                response.raise_for_status()
                data = response.json()
                
                # Validate response
                wrapped = RIPEstatResponse(**data)
                if not wrapped.is_success:
                    raise RIPEstatError(f"API error: {wrapped.data_call_status}")
                
                # Cache successful response
                if self.cache:
                    await self.cache.set(cache_key, wrapped.data, ttl=self.cache_ttl)
                
                return wrapped.data
                
            except httpx.HTTPStatusError as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    
            except httpx.RequestError as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
        
        raise RIPEstatError(f"Request failed after {self.max_retries} attempts: {last_error}")
    
    @staticmethod
    def _format_time(dt: datetime) -> str:
        """Format datetime for RIPEstat API."""
        return dt.strftime("%Y-%m-%dT%H:%M")
    
    @staticmethod
    def _normalize_resource(resource: str) -> str:
        """Normalize ASN or prefix format."""
        resource = resource.strip().upper()
        # Ensure ASN has 'AS' prefix
        if resource.isdigit():
            resource = f"AS{resource}"
        return resource
    
    # ========================================================================
    # API Endpoints
    # ========================================================================
    
    async def get_as_overview(self, asn: str) -> ASOverview:
        """
        Get overview information for an ASN.
        
        Args:
            asn: AS number (e.g., 'AS16509' or '16509')
            
        Returns:
            ASOverview with holder name, announcement status, etc.
        """
        asn = self._normalize_resource(asn)
        data = await self._request("as-overview", {"resource": asn})
        return ASOverview(**data)
    
    async def get_routing_status(self, resource: str) -> RoutingStatus:
        """
        Get current routing status for an ASN or prefix.
        
        Shows visibility, neighbour counts, and announced prefixes.
        
        Args:
            resource: ASN or prefix
            
        Returns:
            RoutingStatus with current routing state
        """
        resource = self._normalize_resource(resource)
        data = await self._request("routing-status", {"resource": resource})
        return RoutingStatus(**data)
    
    async def get_routing_history(
        self,
        resource: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> RoutingHistory:
        """
        Get historical routing information.
        
        Shows how prefixes were announced over time.
        
        Args:
            resource: ASN or prefix
            start_time: Start of time range (default: 7 days ago)
            end_time: End of time range (default: now)
            
        Returns:
            RoutingHistory with timeline of announcements
        """
        resource = self._normalize_resource(resource)
        
        if end_time is None:
            end_time = datetime.utcnow()
        if start_time is None:
            start_time = end_time - timedelta(days=7)
        
        params = {
            "resource": resource,
            "starttime": self._format_time(start_time),
            "endtime": self._format_time(end_time),
        }
        
        data = await self._request("routing-history", params)
        return RoutingHistory(**data)
    
    async def get_bgp_updates(
        self,
        resource: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        rrcs: list[str] | None = None,
    ) -> BGPUpdates:
        """
        Get BGP update activity for a resource.
        
        Shows announcements and withdrawals over time.
        
        Args:
            resource: ASN or prefix
            start_time: Start of time range (default: 1 hour ago)
            end_time: End of time range (default: now)
            rrcs: Specific RRCs to query (default: all)
            
        Returns:
            BGPUpdates with list of update events
        """
        resource = self._normalize_resource(resource)
        
        if end_time is None:
            end_time = datetime.utcnow()
        if start_time is None:
            start_time = end_time - timedelta(hours=1)
        
        params = {
            "resource": resource,
            "starttime": self._format_time(start_time),
            "endtime": self._format_time(end_time),
        }
        if rrcs:
            params["rrcs"] = ",".join(rrcs)
        
        data = await self._request("bgp-updates", params)
        return BGPUpdates(**data)
    
    async def get_announced_prefixes(self, asn: str) -> AnnouncedPrefixes:
        """
        Get all prefixes announced by an ASN.
        
        Args:
            asn: AS number
            
        Returns:
            AnnouncedPrefixes with all current announcements
        """
        asn = self._normalize_resource(asn)
        data = await self._request("announced-prefixes", {"resource": asn})
        return AnnouncedPrefixes(**data)
    
    async def get_as_path_length(self, resource: str) -> ASPathLength:
        """
        Get AS path length statistics.
        
        Args:
            resource: ASN or prefix
            
        Returns:
            ASPathLength with path length distribution
        """
        resource = self._normalize_resource(resource)
        data = await self._request("as-path-length", {"resource": resource})
        return ASPathLength(**data)
    
    async def get_rpki_validation(
        self,
        prefix: str,
        origin_asn: str | None = None,
    ) -> RPKIValidation:
        """
        Get RPKI validation status for a prefix.
        
        Args:
            prefix: IP prefix
            origin_asn: Origin AS (optional, will be detected)
            
        Returns:
            RPKIValidation with ROA status
        """
        params = {"resource": prefix}
        if origin_asn:
            params["origin"] = self._normalize_resource(origin_asn)
        
        data = await self._request("rpki-validation", params)
        return RPKIValidation(**data)
    
    async def get_as_neighbours(
        self,
        asn: str,
        query_time: datetime | None = None,
    ) -> ASNeighbours:
        """
        Get neighbouring ASes (upstreams and downstreams).
        
        Args:
            asn: AS number
            query_time: Historical point in time (default: now)
            
        Returns:
            ASNeighbours with upstream/downstream relationships
        """
        asn = self._normalize_resource(asn)
        params = {"resource": asn}
        if query_time:
            params["query_time"] = self._format_time(query_time)
        
        data = await self._request("asn-neighbours", params)
        return ASNeighbours(**data)
    
    async def get_looking_glass(self, resource: str) -> LookingGlass:
        """
        Query BGP looking glass for current routes.
        
        Shows what different RRCs see for a prefix/ASN.
        
        Args:
            resource: ASN or prefix
            
        Returns:
            LookingGlass with routes from multiple vantage points
        """
        resource = self._normalize_resource(resource)
        data = await self._request("looking-glass", {"resource": resource})
        return LookingGlass(**data)
    
    # ========================================================================
    # Convenience Methods
    # ========================================================================
    
    async def get_prefix_count(self, asn: str) -> dict[str, int]:
        """
        Get count of IPv4 and IPv6 prefixes for an ASN.
        
        Args:
            asn: AS number
            
        Returns:
            Dict with 'ipv4', 'ipv6', and 'total' counts
        """
        prefixes = await self.get_announced_prefixes(asn)
        return {
            "ipv4": len(prefixes.ipv4_prefixes),
            "ipv6": len(prefixes.ipv6_prefixes),
            "total": prefixes.prefix_count,
        }
    
    async def get_upstream_asns(self, asn: str) -> list[int]:
        """
        Get list of upstream (transit provider) ASNs.
        
        Args:
            asn: AS number
            
        Returns:
            List of upstream ASNs sorted by connection count
        """
        neighbours = await self.get_as_neighbours(asn)
        return sorted(
            [n.asn for n in neighbours.upstreams],
            key=lambda a: next(
                (n.power for n in neighbours.upstreams if n.asn == a), 0
            ),
            reverse=True,
        )
    
    async def check_rpki_status(self, asn: str) -> dict[str, list[str]]:
        """
        Check RPKI status for all prefixes announced by an ASN.
        
        Args:
            asn: AS number
            
        Returns:
            Dict with 'valid', 'invalid', 'not_found' prefix lists
        """
        prefixes = await self.get_announced_prefixes(asn)
        
        results: dict[str, list[str]] = {
            "valid": [],
            "invalid": [],
            "not_found": [],
        }
        
        # Check each prefix (with some rate limiting)
        for prefix_obj in prefixes.prefixes:
            try:
                validation = await self.get_rpki_validation(prefix_obj.prefix, asn)
                status_key = validation.status.replace("-", "_")
                if status_key in results:
                    results[status_key].append(prefix_obj.prefix)
                await asyncio.sleep(0.1)  # Be nice to the API
            except RIPEstatError:
                continue
        
        return results


# ============================================================================
# Synchronous Wrapper (for CLI convenience)
# ============================================================================

class RIPEstatClientSync:
    """
    Synchronous wrapper around RIPEstatClient.
    
    Useful for CLI and simple scripts.
    
    Example:
        client = RIPEstatClientSync()
        status = client.get_routing_status("AS16509")
    """
    
    def __init__(self, **kwargs):
        self._async_client = RIPEstatClient(**kwargs)
    
    def _run(self, coro):
        return asyncio.run(self._async_make_request(coro))
    
    async def _async_make_request(self, coro):
        async with self._async_client as client:
            # Re-bind the coroutine to use the initialized client
            method_name = coro.cr_code.co_qualname.split(".")[-1]
            method = getattr(client, method_name)
            # This is hacky - for proper sync wrapper, see below
            pass
        return await coro
    
    def get_as_overview(self, asn: str) -> ASOverview:
        async def _inner():
            async with RIPEstatClient() as client:
                return await client.get_as_overview(asn)
        return asyncio.run(_inner())
    
    def get_routing_status(self, resource: str) -> RoutingStatus:
        async def _inner():
            async with RIPEstatClient() as client:
                return await client.get_routing_status(resource)
        return asyncio.run(_inner())
    
    def get_routing_history(
        self,
        resource: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> RoutingHistory:
        async def _inner():
            async with RIPEstatClient() as client:
                return await client.get_routing_history(resource, start_time, end_time)
        return asyncio.run(_inner())
    
    def get_announced_prefixes(self, asn: str) -> AnnouncedPrefixes:
        async def _inner():
            async with RIPEstatClient() as client:
                return await client.get_announced_prefixes(asn)
        return asyncio.run(_inner())
    
    def get_as_neighbours(self, asn: str) -> ASNeighbours:
        async def _inner():
            async with RIPEstatClient() as client:
                return await client.get_as_neighbours(asn)
        return asyncio.run(_inner())
