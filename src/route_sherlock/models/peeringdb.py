"""
PeeringDB API Models.

Pydantic models for PeeringDB network and facility data.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class InfoType(str, Enum):
    """Network info type."""
    NSP = "NSP"  # Network Service Provider
    CONTENT = "Content"
    CABLE = "Cable/DSL/ISP"
    ENTERPRISE = "Enterprise"
    EDUCATIONAL = "Educational/Research"
    NON_PROFIT = "Non-Profit"
    ROUTE_SERVER = "Route Server"
    GOVERNMENT = "Government"
    OTHER = ""


class InfoScope(str, Enum):
    """Network scope."""
    REGIONAL = "Regional"
    NORTH_AMERICA = "North America"
    ASIA_PACIFIC = "Asia Pacific"
    EUROPE = "Europe"
    SOUTH_AMERICA = "South America"
    AFRICA = "Africa"
    AUSTRALIA = "Australia"
    MIDDLE_EAST = "Middle East"
    GLOBAL = "Global"
    NOT_DISCLOSED = ""


class PolicyGeneral(str, Enum):
    """Peering policy."""
    OPEN = "Open"
    SELECTIVE = "Selective"
    RESTRICTIVE = "Restrictive"
    NO = "No"


class NetixlanStatus(str, Enum):
    """Network-IX connection status."""
    OK = "ok"
    DELETED = "deleted"


class Organization(BaseModel):
    """PeeringDB organization."""
    id: int
    name: str
    aka: str = ""
    name_long: str = ""
    website: str = ""
    notes: str = ""
    address1: str = ""
    address2: str = ""
    city: str = ""
    country: str = ""
    state: str = ""
    zipcode: str = ""
    floor: str = ""
    suite: str = ""
    latitude: float | None = None
    longitude: float | None = None
    created: datetime | None = None
    updated: datetime | None = None
    status: str = "ok"


class Network(BaseModel):
    """PeeringDB network (ASN) record."""
    id: int
    org_id: int
    org: Organization | None = None
    name: str
    aka: str = ""
    name_long: str = ""
    website: str = ""
    asn: int
    looking_glass: str = ""
    route_server: str = ""
    irr_as_set: str = ""
    info_type: str = ""
    info_prefixes4: int | None = None
    info_prefixes6: int | None = None
    info_traffic: str = ""
    info_ratio: str = ""
    info_scope: str = ""
    info_unicast: bool = True
    info_multicast: bool = False
    info_ipv6: bool = False
    info_never_via_route_servers: bool = False
    policy_url: str = ""
    policy_general: str = ""
    policy_locations: str = ""
    policy_ratio: bool = False
    policy_contracts: str = ""
    notes: str = ""
    created: datetime | None = None
    updated: datetime | None = None
    status: str = "ok"

    @property
    def is_open_peering(self) -> bool:
        """Check if network has open peering policy."""
        return self.policy_general.lower() == "open"

    @property
    def total_prefixes(self) -> int:
        """Total announced prefixes (v4 + v6)."""
        return (self.info_prefixes4 or 0) + (self.info_prefixes6 or 0)


class Facility(BaseModel):
    """PeeringDB facility (data center)."""
    id: int
    org_id: int
    org: Organization | None = None
    name: str
    aka: str = ""
    name_long: str = ""
    website: str = ""
    clli: str = ""
    rencode: str = ""
    npanxx: str = ""
    tech_email: str = ""
    tech_phone: str = ""
    sales_email: str = ""
    sales_phone: str = ""
    address1: str = ""
    address2: str = ""
    city: str = ""
    country: str = ""
    state: str = ""
    zipcode: str = ""
    floor: str = ""
    suite: str = ""
    latitude: float | None = None
    longitude: float | None = None
    notes: str = ""
    created: datetime | None = None
    updated: datetime | None = None
    status: str = "ok"


class InternetExchange(BaseModel):
    """PeeringDB Internet Exchange."""
    id: int
    org_id: int
    org: Organization | None = None
    name: str
    aka: str = ""
    name_long: str = ""
    city: str = ""
    country: str = ""
    region_continent: str = ""
    media: str = ""
    notes: str = ""
    proto_unicast: bool = True
    proto_multicast: bool = False
    proto_ipv6: bool = False
    website: str = ""
    url_stats: str = ""
    tech_email: str = ""
    tech_phone: str = ""
    policy_email: str = ""
    policy_phone: str = ""
    ixf_net_count: int = 0
    ixf_last_import: datetime | None = None
    created: datetime | None = None
    updated: datetime | None = None
    status: str = "ok"

    @property
    def member_count(self) -> int:
        """Number of members at this IX."""
        return self.ixf_net_count


class IXLan(BaseModel):
    """IX LAN (peering LAN at an IX)."""
    id: int
    ix_id: int
    name: str = ""
    descr: str = ""
    mtu: int | None = None
    vlan: int | None = None
    dot1q_support: bool = False
    rs_asn: int | None = None
    arp_sponge: str | None = None
    ixf_ixp_member_list_url: str | None = None
    ixf_ixp_member_list_url_visible: str = ""
    created: datetime | None = None
    updated: datetime | None = None
    status: str = "ok"


class IXLanPrefix(BaseModel):
    """IP prefix used on an IX LAN."""
    id: int
    ixlan_id: int
    protocol: str  # "IPv4" or "IPv6"
    prefix: str
    in_dfz: bool = False
    created: datetime | None = None
    updated: datetime | None = None
    status: str = "ok"


class NetworkIXLan(BaseModel):
    """Network's connection to an IX (netixlan)."""
    id: int
    net_id: int
    ix_id: int
    ixlan_id: int
    name: str = ""
    notes: str = ""
    speed: int = 0  # Port speed in Mbps
    asn: int
    ipaddr4: str | None = None
    ipaddr6: str | None = None
    is_rs_peer: bool = False
    operational: bool = True
    created: datetime | None = None
    updated: datetime | None = None
    status: str = "ok"

    @property
    def speed_gbps(self) -> float:
        """Port speed in Gbps."""
        return self.speed / 1000 if self.speed else 0


class NetworkFacility(BaseModel):
    """Network's presence at a facility."""
    id: int
    net_id: int
    fac_id: int
    name: str = ""
    city: str = ""
    country: str = ""
    local_asn: int | None = None
    avail_sonet: bool = False
    avail_ethernet: bool = False
    avail_atm: bool = False
    created: datetime | None = None
    updated: datetime | None = None
    status: str = "ok"


class NetworkContact(BaseModel):
    """Network contact information."""
    id: int
    net_id: int
    role: str = ""
    visible: str = "Users"
    name: str = ""
    phone: str = ""
    email: str = ""
    url: str = ""
    created: datetime | None = None
    updated: datetime | None = None
    status: str = "ok"


class IXFacility(BaseModel):
    """IX presence at a facility."""
    id: int
    ix_id: int
    fac_id: int
    name: str = ""
    city: str = ""
    country: str = ""
    created: datetime | None = None
    updated: datetime | None = None
    status: str = "ok"


# Response containers

class NetworkList(BaseModel):
    """List of networks."""
    data: list[Network] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


class FacilityList(BaseModel):
    """List of facilities."""
    data: list[Facility] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


class IXList(BaseModel):
    """List of Internet Exchanges."""
    data: list[InternetExchange] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


class NetworkPresence(BaseModel):
    """Summary of a network's presence."""
    asn: int
    name: str
    ix_count: int = 0
    facility_count: int = 0
    exchanges: list[InternetExchange] = Field(default_factory=list)
    facilities: list[Facility] = Field(default_factory=list)
    connections: list[NetworkIXLan] = Field(default_factory=list)


class CommonIX(BaseModel):
    """Common IX between two networks."""
    ix: InternetExchange
    net1_connection: NetworkIXLan
    net2_connection: NetworkIXLan

    @property
    def can_peer(self) -> bool:
        """Check if both have IPs on same address family."""
        has_v4 = (self.net1_connection.ipaddr4 and self.net2_connection.ipaddr4)
        has_v6 = (self.net1_connection.ipaddr6 and self.net2_connection.ipaddr6)
        return has_v4 or has_v6


class PeeringOpportunity(BaseModel):
    """Potential peering opportunity between two ASNs."""
    asn1: int
    asn2: int
    net1_name: str = ""
    net2_name: str = ""
    common_ixes: list[CommonIX] = Field(default_factory=list)
    common_facilities: list[Facility] = Field(default_factory=list)

    @property
    def opportunity_count(self) -> int:
        """Total number of peering opportunities."""
        return len(self.common_ixes) + len(self.common_facilities)
