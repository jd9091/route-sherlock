"""
RIPE Atlas API Models.

Pydantic models for RIPE Atlas measurement and probe data.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ProbeStatus(str, Enum):
    """Probe connection status."""
    CONNECTED = "Connected"
    DISCONNECTED = "Disconnected"
    ABANDONED = "Abandoned"
    NEVER_CONNECTED = "NeverConnected"


class MeasurementType(str, Enum):
    """Atlas measurement types."""
    PING = "ping"
    TRACEROUTE = "traceroute"
    DNS = "dns"
    SSL = "sslcert"
    NTP = "ntp"
    HTTP = "http"


class MeasurementStatus(str, Enum):
    """Measurement status values."""
    SPECIFIED = "Specified"
    SCHEDULED = "Scheduled"
    ONGOING = "Ongoing"
    STOPPED = "Stopped"
    FORCED_STOP = "Forced to stop"
    NO_SUITABLE_PROBES = "No suitable probes"
    FAILED = "Failed"


class ProbeGeometry(BaseModel):
    """Probe location geometry."""
    type: str = "Point"
    coordinates: list[float] = Field(default_factory=list)


class ProbeLocation(BaseModel):
    """Probe geographic location."""
    country_code: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None


class ProbeTag(BaseModel):
    """Probe tag."""
    name: str
    slug: str


class ProbeStatusInfo(BaseModel):
    """Probe status info from API."""
    id: int
    name: str

    class Config:
        extra = "ignore"


class Probe(BaseModel):
    """RIPE Atlas probe information."""
    id: int
    asn_v4: int | None = None
    asn_v6: int | None = None
    country_code: str | None = None
    description: str | None = None
    address_v4: str | None = None
    address_v6: str | None = None
    prefix_v4: str | None = None
    prefix_v6: str | None = None
    is_anchor: bool = False
    status: ProbeStatusInfo | dict | None = None
    status_since: datetime | None = None
    first_connected: datetime | None = None
    last_connected: datetime | None = None
    geometry: ProbeGeometry | None = None
    tags: list[ProbeTag | dict] = Field(default_factory=list)

    class Config:
        extra = "ignore"

    @property
    def is_connected(self) -> bool:
        """Check if probe is currently connected."""
        if isinstance(self.status, dict):
            return self.status.get("name") == "Connected"
        elif isinstance(self.status, ProbeStatusInfo):
            return self.status.name == "Connected"
        return False

    @property
    def asn(self) -> int | None:
        """Return primary ASN (prefer v4)."""
        return self.asn_v4 or self.asn_v6


class ProbeList(BaseModel):
    """List of probes with pagination info."""
    count: int = 0
    next: str | None = None
    previous: str | None = None
    probes: list[Probe] = Field(default_factory=list)


class Anchor(BaseModel):
    """RIPE Atlas anchor information."""
    id: int
    fqdn: str
    probe_id: int | None = None
    country_code: str | None = None
    city: str | None = None
    company: str | None = None
    asn_v4: int | None = None
    asn_v6: int | None = None
    ip_v4: str | None = None
    ip_v6: str | None = None
    is_disabled: bool = False
    geometry: ProbeGeometry | None = None


class AnchorList(BaseModel):
    """List of anchors with pagination."""
    count: int = 0
    next: str | None = None
    previous: str | None = None
    anchors: list[Anchor] = Field(default_factory=list)


class MeasurementDefinition(BaseModel):
    """Measurement configuration."""
    id: int
    type: MeasurementType
    target: str | None = None
    description: str | None = None
    af: int = 4  # Address family: 4 or 6
    status: MeasurementStatus | None = None
    is_oneoff: bool = False
    interval: int | None = None
    spread: int | None = None
    creation_time: datetime | None = None
    start_time: datetime | None = None
    stop_time: datetime | None = None
    participant_count: int | None = None
    probes_requested: int | None = None
    probes_scheduled: int | None = None
    is_all_scheduled: bool = False


class PingResult(BaseModel):
    """Result from a ping measurement."""
    probe_id: int
    timestamp: int
    from_addr: str | None = Field(None, alias="from")
    dst_addr: str | None = None
    dst_name: str | None = None
    min_rtt: float | None = Field(None, alias="min")
    max_rtt: float | None = Field(None, alias="max")
    avg_rtt: float | None = Field(None, alias="avg")
    sent: int = 0
    rcvd: int = 0
    dup: int = 0
    ttl: int | None = None
    size: int | None = None

    class Config:
        populate_by_name = True

    @property
    def packet_loss(self) -> float:
        """Calculate packet loss percentage."""
        if self.sent == 0:
            return 0.0
        return ((self.sent - self.rcvd) / self.sent) * 100


class TracerouteHop(BaseModel):
    """Single hop in a traceroute."""
    hop: int
    from_addr: str | None = Field(None, alias="from")
    rtt: float | None = None
    ttl: int | None = None
    size: int | None = None
    err: str | None = None
    late: int | None = None
    dup: bool = False

    class Config:
        populate_by_name = True


class TracerouteResult(BaseModel):
    """Result from a traceroute measurement."""
    probe_id: int
    timestamp: int
    from_addr: str | None = Field(None, alias="from")
    dst_addr: str | None = None
    dst_name: str | None = None
    paris_id: int | None = None
    size: int | None = None
    hops: list[TracerouteHop] = Field(default_factory=list)

    class Config:
        populate_by_name = True

    @property
    def hop_count(self) -> int:
        """Return total number of hops."""
        return len(self.hops) if self.hops else 0

    @property
    def reached_destination(self) -> bool:
        """Check if traceroute reached destination."""
        if not self.hops or not self.dst_addr:
            return False
        last_hop = self.hops[-1] if self.hops else None
        return last_hop is not None and last_hop.from_addr == self.dst_addr


class DnsAnswer(BaseModel):
    """Single DNS answer record."""
    name: str | None = None
    type: str | None = Field(None, alias="TYPE")
    rdata: str | None = Field(None, alias="RDATA")
    ttl: int | None = Field(None, alias="TTL")

    class Config:
        populate_by_name = True


class DnsResult(BaseModel):
    """Result from a DNS measurement."""
    probe_id: int
    timestamp: int
    from_addr: str | None = Field(None, alias="from")
    dst_addr: str | None = None
    rt: float | None = None  # Response time
    answers: list[DnsAnswer] = Field(default_factory=list)
    ancount: int = 0
    arcount: int = 0
    nscount: int = 0
    qdcount: int = 0
    rcode: int | None = Field(None, alias="RCODE")
    error: str | None = None

    class Config:
        populate_by_name = True

    @property
    def is_success(self) -> bool:
        """Check if DNS query was successful."""
        return self.rcode == 0 and self.error is None


class SslCertificate(BaseModel):
    """SSL certificate information."""
    subject: str | None = None
    issuer: str | None = None
    valid_from: str | None = None
    valid_to: str | None = None
    fingerprint: str | None = None
    serial: str | None = None


class SslResult(BaseModel):
    """Result from an SSL measurement."""
    probe_id: int
    timestamp: int
    from_addr: str | None = Field(None, alias="from")
    dst_addr: str | None = None
    dst_port: int | None = None
    rt: float | None = None
    ttc: float | None = None  # Time to connect
    certificates: list[SslCertificate] = Field(default_factory=list)
    error: str | None = None
    alert: str | None = None

    class Config:
        populate_by_name = True

    @property
    def is_success(self) -> bool:
        """Check if SSL handshake was successful."""
        return self.error is None and self.alert is None


class MeasurementResults(BaseModel):
    """Container for measurement results."""
    measurement_id: int
    type: MeasurementType | None = None
    results: list[dict[str, Any]] = Field(default_factory=list)

    def get_ping_results(self) -> list[PingResult]:
        """Parse results as ping measurements."""
        return [PingResult(**r) for r in self.results if "avg" in r or "min" in r]

    def get_traceroute_results(self) -> list[TracerouteResult]:
        """Parse results as traceroute measurements."""
        return [TracerouteResult(**r) for r in self.results if "result" in r or "hops" in r]

    def get_dns_results(self) -> list[DnsResult]:
        """Parse results as DNS measurements."""
        return [DnsResult(**r) for r in self.results if "answers" in r or "RCODE" in r]


class BuiltinMeasurement(BaseModel):
    """Built-in anchor measurement info."""
    measurement_id: int
    type: MeasurementType
    target: str
    target_ip: str | None = None
    af: int = 4
    description: str | None = None
