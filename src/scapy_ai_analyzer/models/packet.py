"""Normalized packet record.

A ``PacketRecord`` is the single normalized representation of one captured frame.
Every downstream module (flow analysis, rules, AI, reports) consumes this type,
never a raw Scapy packet. Missing protocol fields are ``None`` -- they are never
filled with invented values.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

# Parse status values.
PARSE_OK = "ok"
PARSE_PARTIAL = "partial"
PARSE_FAILED = "failed"


@dataclass
class PacketRecord:
    """One normalized packet.

    Attributes are intentionally flat and JSON-serializable. Protocol sections
    that do not exist in the frame stay ``None``.
    """

    packet_id: int
    timestamp: float
    source_type: str  # "file" | "live"
    captured_length: int
    original_length: Optional[int] = None
    source_ref: Optional[str] = None  # e.g. file path or interface name
    frame_number: Optional[int] = None  # 1-based index in the capture

    # Ethernet
    eth_src: Optional[str] = None
    eth_dst: Optional[str] = None
    eth_type: Optional[int] = None

    # VLAN
    vlan_id: Optional[int] = None
    vlan_priority: Optional[int] = None

    # Network layer (IPv4 / IPv6 / ARP)
    network_layer: Optional[str] = None  # "IPv4" | "IPv6" | "ARP"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_version: Optional[int] = None
    ip_protocol: Optional[int] = None
    ip_protocol_name: Optional[str] = None
    ttl: Optional[int] = None  # TTL (IPv4) or Hop Limit (IPv6)
    ip_length: Optional[int] = None
    ip_flags: Optional[str] = None

    # ARP
    arp_op: Optional[int] = None
    arp_psrc: Optional[str] = None
    arp_pdst: Optional[str] = None

    # Transport
    transport_protocol: Optional[str] = None  # "TCP" | "UDP" | "ICMP" | ...
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # TCP
    tcp_flags: Optional[str] = None
    tcp_flags_int: Optional[int] = None
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_window: Optional[int] = None
    payload_length: Optional[int] = None

    # UDP
    udp_length: Optional[int] = None

    # ICMP / ICMPv6
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    icmp_id: Optional[int] = None
    icmp_seq: Optional[int] = None

    # DNS
    dns_query: Optional[str] = None
    dns_query_type: Optional[str] = None
    dns_is_response: Optional[bool] = None
    dns_rcode: Optional[str] = None
    dns_answers: list[str] = field(default_factory=list)
    dns_id: Optional[int] = None

    # HTTP (metadata only, never bodies by default)
    http_method: Optional[str] = None
    http_host: Optional[str] = None
    http_uri: Optional[str] = None
    http_status: Optional[int] = None
    http_user_agent: Optional[str] = None

    # TLS handshake metadata (no decryption)
    tls_sni: Optional[str] = None
    tls_version: Optional[str] = None
    tls_handshake_type: Optional[str] = None

    # Analysis bookkeeping
    protocols: list[str] = field(default_factory=list)
    parse_status: str = PARSE_OK
    parse_warnings: list[str] = field(default_factory=list)

    @property
    def is_ipv6(self) -> bool:
        return self.ip_version == 6

    def transport_endpoints(self) -> Optional[tuple[str, int, str, int]]:
        """Return ``(src_ip, src_port, dst_ip, dst_port)`` when fully available."""
        if self.src_ip and self.dst_ip and self.src_port is not None and self.dst_port is not None:
            return (self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        return None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        # ``is_ipv6`` is a property, added explicitly for report consumers.
        data["is_ipv6"] = self.is_ipv6
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PacketRecord":
        payload = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**payload)


def normalize_ip(value: Optional[str]) -> Optional[str]:
    """Canonicalize an IP string without conflating IPv4 and IPv6."""
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value
