"""
PeeringDB API Client.

Async client for querying PeeringDB network interconnection database.
Documentation: https://www.peeringdb.com/apidocs/

Usage:
    async with PeeringDBClient() as client:
        network = await client.get_network_by_asn(16509)
        print(f"{network.name}: {network.policy_general} peering")
"""
from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlencode

import httpx

from route_sherlock.models.peeringdb import (
    CommonIX,
    Facility,
    InternetExchange,
    IXLan,
    IXLanPrefix,
    Network,
    NetworkFacility,
    NetworkIXLan,
    NetworkPresence,
    Organization,
    PeeringOpportunity,
)
from route_sherlock.cache.store import Cache


class PeeringDBError(Exception):
    """Base exception for PeeringDB API errors."""
    pass


class PeeringDBAuthError(PeeringDBError):
    """Raised when authentication fails."""
    pass


class PeeringDBRateLimitError(PeeringDBError):
    """Raised when rate limit is exceeded."""
    pass


class PeeringDBNotFoundError(PeeringDBError):
    """Raised when a resource is not found."""
    pass


class PeeringDBClient:
    """
    Async client for PeeringDB API.

    Anonymous access is allowed with rate limits.
    Authentication provides higher rate limits.

    Example:
        async with PeeringDBClient() as client:
            # Get network info
            net = await client.get_network_by_asn(16509)
            print(f"{net.name}: {net.info_prefixes4} IPv4 prefixes")

            # Find common IXes between two networks
            common = await client.find_common_ixes(16509, 13335)
    """

    BASE_URL = "https://www.peeringdb.com/api"

    def __init__(
        self,
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        cache: Cache | None = None,
        cache_ttl: int = 3600,  # 1 hour default
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        """
        Initialize PeeringDB client.

        Args:
            api_key: PeeringDB API key (preferred auth method)
            username: PeeringDB username (alternative auth)
            password: PeeringDB password (with username)
            cache: Optional cache instance for response caching
            cache_ttl: Cache time-to-live in seconds
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts for failed requests
        """
        self.api_key = api_key
        self.username = username
        self.password = password
        self.cache = cache
        self.cache_ttl = cache_ttl
        self.timeout = timeout
        self.max_retries = max_retries
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "PeeringDBClient":
        headers = {"Accept": "application/json"}

        auth = None
        if self.api_key:
            headers["Authorization"] = f"Api-Key {self.api_key}"
        elif self.username and self.password:
            auth = httpx.BasicAuth(self.username, self.password)

        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            headers=headers,
            auth=auth,
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
    ) -> dict[str, Any]:
        """
        Make a request to PeeringDB API.

        Args:
            endpoint: API endpoint (e.g., 'net', 'ix')
            params: Query parameters
            use_cache: Whether to use cached response if available

        Returns:
            Parsed JSON response
        """
        if not self._client:
            raise PeeringDBError("Client not initialized. Use 'async with' context manager.")

        params = params or {}

        # Build cache key
        cache_key = f"peeringdb:{endpoint}:{urlencode(sorted(params.items()))}"

        # Check cache
        if use_cache and self.cache:
            cached = await self.cache.get(cache_key)
            if cached is not None:
                return cached

        # Build URL
        url = f"{self.BASE_URL}/{endpoint}"

        # Make request with retries
        last_error: Exception | None = None
        for attempt in range(self.max_retries):
            try:
                response = await self._client.get(url, params=params)

                if response.status_code == 401:
                    raise PeeringDBAuthError("Authentication failed")
                if response.status_code == 403:
                    raise PeeringDBAuthError("Access denied")
                if response.status_code == 404:
                    raise PeeringDBNotFoundError(f"Resource not found: {endpoint}")
                if response.status_code == 429:
                    raise PeeringDBRateLimitError("Rate limit exceeded")

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

        raise PeeringDBError(f"Request failed after {self.max_retries} attempts: {last_error}")

    def _extract_data(self, response: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract data array from response."""
        return response.get("data", [])

    def _extract_single(self, response: dict[str, Any]) -> dict[str, Any] | None:
        """Extract single item from response."""
        data = self._extract_data(response)
        return data[0] if data else None

    # ========================================================================
    # Network Endpoints
    # ========================================================================

    async def get_network(self, net_id: int) -> Network:
        """
        Get network by PeeringDB ID.

        Args:
            net_id: PeeringDB network ID

        Returns:
            Network record
        """
        data = await self._request(f"net/{net_id}")
        item = self._extract_single(data)
        if not item:
            raise PeeringDBNotFoundError(f"Network {net_id} not found")
        return Network(**item)

    async def get_network_by_asn(self, asn: int) -> Network:
        """
        Get network by ASN.

        Args:
            asn: AS number

        Returns:
            Network record
        """
        data = await self._request("net", {"asn": asn})
        item = self._extract_single(data)
        if not item:
            raise PeeringDBNotFoundError(f"ASN {asn} not found in PeeringDB")
        return Network(**item)

    async def search_networks(
        self,
        name: str | None = None,
        asn: int | None = None,
        info_type: str | None = None,
        policy_general: str | None = None,
        country: str | None = None,
        limit: int = 100,
    ) -> list[Network]:
        """
        Search for networks.

        Args:
            name: Search by name (partial match)
            asn: Filter by ASN
            info_type: Filter by network type
            policy_general: Filter by peering policy
            country: Filter by country (via org)
            limit: Maximum results

        Returns:
            List of matching networks
        """
        params: dict[str, Any] = {"limit": limit}

        if name:
            params["name__contains"] = name
        if asn:
            params["asn"] = asn
        if info_type:
            params["info_type"] = info_type
        if policy_general:
            params["policy_general"] = policy_general

        data = await self._request("net", params)
        return [Network(**n) for n in self._extract_data(data)]

    async def get_network_ixlans(self, asn: int) -> list[NetworkIXLan]:
        """
        Get all IX connections for a network.

        Args:
            asn: AS number

        Returns:
            List of IX connections
        """
        data = await self._request("netixlan", {"asn": asn})
        return [NetworkIXLan(**n) for n in self._extract_data(data)]

    async def get_network_facilities(self, asn: int) -> list[NetworkFacility]:
        """
        Get all facility presences for a network.

        Args:
            asn: AS number

        Returns:
            List of facility connections
        """
        # First get net_id from ASN
        network = await self.get_network_by_asn(asn)
        data = await self._request("netfac", {"net_id": network.id})
        return [NetworkFacility(**n) for n in self._extract_data(data)]

    # ========================================================================
    # Internet Exchange Endpoints
    # ========================================================================

    async def get_ix(self, ix_id: int) -> InternetExchange:
        """
        Get Internet Exchange by ID.

        Args:
            ix_id: PeeringDB IX ID

        Returns:
            InternetExchange record
        """
        data = await self._request(f"ix/{ix_id}")
        item = self._extract_single(data)
        if not item:
            raise PeeringDBNotFoundError(f"IX {ix_id} not found")
        return InternetExchange(**item)

    async def search_ixes(
        self,
        name: str | None = None,
        country: str | None = None,
        city: str | None = None,
        region: str | None = None,
        limit: int = 100,
    ) -> list[InternetExchange]:
        """
        Search for Internet Exchanges.

        Args:
            name: Search by name
            country: Filter by country code
            city: Filter by city
            region: Filter by region/continent
            limit: Maximum results

        Returns:
            List of matching IXes
        """
        params: dict[str, Any] = {"limit": limit}

        if name:
            params["name__contains"] = name
        if country:
            params["country"] = country.upper()
        if city:
            params["city__contains"] = city
        if region:
            params["region_continent"] = region

        data = await self._request("ix", params)
        return [InternetExchange(**ix) for ix in self._extract_data(data)]

    async def get_ix_members(self, ix_id: int) -> list[NetworkIXLan]:
        """
        Get all members of an IX.

        Args:
            ix_id: PeeringDB IX ID

        Returns:
            List of network connections at this IX
        """
        data = await self._request("netixlan", {"ix_id": ix_id})
        return [NetworkIXLan(**n) for n in self._extract_data(data)]

    async def get_ix_prefixes(self, ix_id: int) -> list[IXLanPrefix]:
        """
        Get peering LAN prefixes for an IX.

        Args:
            ix_id: PeeringDB IX ID

        Returns:
            List of prefixes
        """
        # First get ixlan_id
        data = await self._request("ixlan", {"ix_id": ix_id})
        ixlans = self._extract_data(data)

        prefixes = []
        for ixlan in ixlans:
            prefix_data = await self._request("ixpfx", {"ixlan_id": ixlan["id"]})
            prefixes.extend([IXLanPrefix(**p) for p in self._extract_data(prefix_data)])

        return prefixes

    # ========================================================================
    # Facility Endpoints
    # ========================================================================

    async def get_facility(self, fac_id: int) -> Facility:
        """
        Get facility by ID.

        Args:
            fac_id: PeeringDB facility ID

        Returns:
            Facility record
        """
        data = await self._request(f"fac/{fac_id}")
        item = self._extract_single(data)
        if not item:
            raise PeeringDBNotFoundError(f"Facility {fac_id} not found")
        return Facility(**item)

    async def search_facilities(
        self,
        name: str | None = None,
        country: str | None = None,
        city: str | None = None,
        limit: int = 100,
    ) -> list[Facility]:
        """
        Search for facilities.

        Args:
            name: Search by name
            country: Filter by country code
            city: Filter by city
            limit: Maximum results

        Returns:
            List of matching facilities
        """
        params: dict[str, Any] = {"limit": limit}

        if name:
            params["name__contains"] = name
        if country:
            params["country"] = country.upper()
        if city:
            params["city__contains"] = city

        data = await self._request("fac", params)
        return [Facility(**f) for f in self._extract_data(data)]

    async def get_facility_networks(self, fac_id: int) -> list[NetworkFacility]:
        """
        Get all networks present at a facility.

        Args:
            fac_id: PeeringDB facility ID

        Returns:
            List of networks at this facility
        """
        data = await self._request("netfac", {"fac_id": fac_id})
        return [NetworkFacility(**n) for n in self._extract_data(data)]

    # ========================================================================
    # Organization Endpoints
    # ========================================================================

    async def get_organization(self, org_id: int) -> Organization:
        """
        Get organization by ID.

        Args:
            org_id: PeeringDB organization ID

        Returns:
            Organization record
        """
        data = await self._request(f"org/{org_id}")
        item = self._extract_single(data)
        if not item:
            raise PeeringDBNotFoundError(f"Organization {org_id} not found")
        return Organization(**item)

    # ========================================================================
    # Peering Analysis
    # ========================================================================

    async def get_network_presence(self, asn: int) -> NetworkPresence:
        """
        Get comprehensive presence information for a network.

        Args:
            asn: AS number

        Returns:
            NetworkPresence with all IX and facility data
        """
        network = await self.get_network_by_asn(asn)
        connections = await self.get_network_ixlans(asn)
        net_facilities = await self.get_network_facilities(asn)

        # Get IX details
        ix_ids = set(c.ix_id for c in connections)
        exchanges = []
        for ix_id in ix_ids:
            try:
                ix = await self.get_ix(ix_id)
                exchanges.append(ix)
            except PeeringDBNotFoundError:
                continue

        # Get facility details
        fac_ids = set(nf.fac_id for nf in net_facilities)
        facilities = []
        for fac_id in fac_ids:
            try:
                fac = await self.get_facility(fac_id)
                facilities.append(fac)
            except PeeringDBNotFoundError:
                continue

        return NetworkPresence(
            asn=asn,
            name=network.name,
            ix_count=len(exchanges),
            facility_count=len(facilities),
            exchanges=exchanges,
            facilities=facilities,
            connections=connections,
        )

    async def find_common_ixes(self, asn1: int, asn2: int) -> list[CommonIX]:
        """
        Find common Internet Exchanges between two networks.

        Args:
            asn1: First AS number
            asn2: Second AS number

        Returns:
            List of common IXes with connection details
        """
        conn1 = await self.get_network_ixlans(asn1)
        conn2 = await self.get_network_ixlans(asn2)

        # Index by IX ID
        ix_map1 = {c.ix_id: c for c in conn1}
        ix_map2 = {c.ix_id: c for c in conn2}

        common_ix_ids = set(ix_map1.keys()) & set(ix_map2.keys())

        common = []
        for ix_id in common_ix_ids:
            try:
                ix = await self.get_ix(ix_id)
                common.append(CommonIX(
                    ix=ix,
                    net1_connection=ix_map1[ix_id],
                    net2_connection=ix_map2[ix_id],
                ))
            except PeeringDBNotFoundError:
                continue

        return common

    async def find_common_facilities(self, asn1: int, asn2: int) -> list[Facility]:
        """
        Find common facilities between two networks.

        Args:
            asn1: First AS number
            asn2: Second AS number

        Returns:
            List of common facilities
        """
        fac1 = await self.get_network_facilities(asn1)
        fac2 = await self.get_network_facilities(asn2)

        fac_ids1 = set(f.fac_id for f in fac1)
        fac_ids2 = set(f.fac_id for f in fac2)

        common_fac_ids = fac_ids1 & fac_ids2

        facilities = []
        for fac_id in common_fac_ids:
            try:
                fac = await self.get_facility(fac_id)
                facilities.append(fac)
            except PeeringDBNotFoundError:
                continue

        return facilities

    async def find_peering_opportunities(
        self,
        asn1: int,
        asn2: int,
    ) -> PeeringOpportunity:
        """
        Find all peering opportunities between two networks.

        Args:
            asn1: First AS number
            asn2: Second AS number

        Returns:
            PeeringOpportunity with all common locations
        """
        net1 = await self.get_network_by_asn(asn1)
        net2 = await self.get_network_by_asn(asn2)

        common_ixes = await self.find_common_ixes(asn1, asn2)
        common_facilities = await self.find_common_facilities(asn1, asn2)

        return PeeringOpportunity(
            asn1=asn1,
            asn2=asn2,
            net1_name=net1.name,
            net2_name=net2.name,
            common_ixes=common_ixes,
            common_facilities=common_facilities,
        )

    async def get_open_peering_networks_at_ix(self, ix_id: int) -> list[Network]:
        """
        Get networks with open peering policy at an IX.

        Args:
            ix_id: PeeringDB IX ID

        Returns:
            List of networks with open peering
        """
        members = await self.get_ix_members(ix_id)
        asns = set(m.asn for m in members)

        open_networks = []
        for asn in asns:
            try:
                network = await self.get_network_by_asn(asn)
                if network.is_open_peering:
                    open_networks.append(network)
            except PeeringDBNotFoundError:
                continue
            await asyncio.sleep(0.05)  # Rate limit

        return open_networks

    # ========================================================================
    # Convenience Methods
    # ========================================================================

    async def get_asn_summary(self, asn: int) -> dict[str, Any]:
        """
        Get summary information for an ASN.

        Args:
            asn: AS number

        Returns:
            Dict with network info, IX count, facility count
        """
        try:
            network = await self.get_network_by_asn(asn)
        except PeeringDBNotFoundError:
            return {"asn": asn, "in_peeringdb": False}

        connections = await self.get_network_ixlans(asn)
        facilities = await self.get_network_facilities(asn)

        return {
            "asn": asn,
            "in_peeringdb": True,
            "name": network.name,
            "policy": network.policy_general,
            "info_type": network.info_type,
            "prefixes_v4": network.info_prefixes4,
            "prefixes_v6": network.info_prefixes6,
            "ix_count": len(set(c.ix_id for c in connections)),
            "facility_count": len(set(f.fac_id for f in facilities)),
            "website": network.website,
            "irr_as_set": network.irr_as_set,
        }


# ============================================================================
# Synchronous Wrapper
# ============================================================================

class PeeringDBClientSync:
    """
    Synchronous wrapper around PeeringDBClient.

    Useful for CLI and simple scripts.

    Example:
        client = PeeringDBClientSync()
        network = client.get_network_by_asn(16509)
    """

    def __init__(self, **kwargs):
        self._kwargs = kwargs

    def get_network_by_asn(self, asn: int) -> Network:
        async def _inner():
            async with PeeringDBClient(**self._kwargs) as client:
                return await client.get_network_by_asn(asn)
        return asyncio.run(_inner())

    def get_network_ixlans(self, asn: int) -> list[NetworkIXLan]:
        async def _inner():
            async with PeeringDBClient(**self._kwargs) as client:
                return await client.get_network_ixlans(asn)
        return asyncio.run(_inner())

    def get_network_facilities(self, asn: int) -> list[NetworkFacility]:
        async def _inner():
            async with PeeringDBClient(**self._kwargs) as client:
                return await client.get_network_facilities(asn)
        return asyncio.run(_inner())

    def get_network_presence(self, asn: int) -> NetworkPresence:
        async def _inner():
            async with PeeringDBClient(**self._kwargs) as client:
                return await client.get_network_presence(asn)
        return asyncio.run(_inner())

    def find_common_ixes(self, asn1: int, asn2: int) -> list[CommonIX]:
        async def _inner():
            async with PeeringDBClient(**self._kwargs) as client:
                return await client.find_common_ixes(asn1, asn2)
        return asyncio.run(_inner())

    def find_peering_opportunities(
        self,
        asn1: int,
        asn2: int,
    ) -> PeeringOpportunity:
        async def _inner():
            async with PeeringDBClient(**self._kwargs) as client:
                return await client.find_peering_opportunities(asn1, asn2)
        return asyncio.run(_inner())

    def get_asn_summary(self, asn: int) -> dict[str, Any]:
        async def _inner():
            async with PeeringDBClient(**self._kwargs) as client:
                return await client.get_asn_summary(asn)
        return asyncio.run(_inner())

    def search_ixes(
        self,
        name: str | None = None,
        country: str | None = None,
    ) -> list[InternetExchange]:
        async def _inner():
            async with PeeringDBClient(**self._kwargs) as client:
                return await client.search_ixes(name=name, country=country)
        return asyncio.run(_inner())
