"""Flow (conversation) model.

A flow groups related packets. The flow key is canonicalized so that the same
conversation yields the same key regardless of which direction the first packet
traveled. Direction-specific counters keep both halves of the conversation apart.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional

# TCP flag bit masks, used for flag accounting.
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


@dataclass
class Flow:
    """A bidirectional conversation between two endpoints."""

    flow_id: str
    src_ip: str
    dst_ip: str
    transport_protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    start_time: float = 0.0
    end_time: float = 0.0

    packet_count: int = 0
    # Packets sent from the canonical src endpoint toward dst, and vice versa.
    packets_forward: int = 0
    packets_reverse: int = 0
    bytes_forward: int = 0
    bytes_reverse: int = 0

    tcp_flag_counts: dict[str, int] = field(default_factory=dict)
    packet_ids: list[int] = field(default_factory=list)

    # Populated by later analysis stages.
    dns_query_count: int = 0
    dns_queries: list[str] = field(default_factory=list)
    http_hosts: list[str] = field(default_factory=list)
    tls_snis: list[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(0.0, self.end_time - self.start_time)

    @property
    def total_bytes(self) -> int:
        return self.bytes_forward + self.bytes_reverse

    @property
    def total_packets(self) -> int:
        return self.packets_forward + self.packets_reverse

    @property
    def syn_count(self) -> int:
        return self.tcp_flag_counts.get("SYN", 0)

    @property
    def rst_count(self) -> int:
        return self.tcp_flag_counts.get("RST", 0)

    @property
    def fin_count(self) -> int:
        return self.tcp_flag_counts.get("FIN", 0)

    @property
    def is_syn_only(self) -> bool:
        """True when SYN was seen but never followed by ACK/FIN/RST."""
        return (
            self.syn_count > 0
            and self.tcp_flag_counts.get("ACK", 0) == 0
            and self.fin_count == 0
            and self.rst_count == 0
        )

    def key(self) -> str:
        return self.flow_id

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["duration"] = round(self.duration, 6)
        data["total_bytes"] = self.total_bytes
        data["total_packets"] = self.total_packets
        data["is_syn_only"] = self.is_syn_only
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Flow":
        payload = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**payload)


def make_flow_key(
    src_ip: str,
    dst_ip: str,
    transport_protocol: str,
    src_port: Optional[int],
    dst_port: Optional[int],
) -> tuple[str, str, Optional[int], Optional[int], str]:
    """Build a direction-independent flow key.

    The two endpoints are sorted so that A->B and B->A map to one key. The
    protocol is part of the key: a TCP and a UDP conversation between the same
    port pair are distinct flows.
    """
    endpoint_a = (src_ip, src_port if src_port is not None else -1)
    endpoint_b = (dst_ip, dst_port if dst_port is not None else -1)
    if endpoint_a <= endpoint_b:
        first, second = endpoint_a, endpoint_b
    else:
        first, second = endpoint_b, endpoint_a
    return (first[0], second[0], first[1], second[1], transport_protocol.upper())
