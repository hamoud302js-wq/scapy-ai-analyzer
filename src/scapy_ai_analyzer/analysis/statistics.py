"""Traffic statistics.

Produces the aggregate numbers that later stages (rules and AI) reason about.
All values are derived from observed packets; nothing is extrapolated or
estimated.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Iterable, Optional

from ..models.flow import Flow
from ..models.packet import PacketRecord


@dataclass
class HostStatistics:
    """Per-IP counters."""

    ip: str
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    distinct_dst_ports: int = 0
    distinct_dst_ips: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TrafficStatistics:
    """Session-wide statistics."""

    total_packets: int = 0
    total_bytes: int = 0
    first_timestamp: Optional[float] = None
    last_timestamp: Optional[float] = None
    duration_seconds: float = 0.0
    protocol_counts: dict[str, int] = field(default_factory=dict)
    transport_counts: dict[str, int] = field(default_factory=dict)
    ethertype_counts: dict[str, int] = field(default_factory=dict)
    top_src_ips: list[tuple[str, int]] = field(default_factory=list)
    top_dst_ips: list[tuple[str, int]] = field(default_factory=list)
    top_dst_ports: list[tuple[str, int]] = field(default_factory=list)
    tcp_flag_totals: dict[str, int] = field(default_factory=dict)
    dns_query_count: int = 0
    dns_response_count: int = 0
    dns_nxdomain_count: int = 0
    dns_top_queries: list[tuple[str, int]] = field(default_factory=list)
    parse_status_counts: dict[str, int] = field(default_factory=dict)
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    host_statistics: dict[str, HostStatistics] = field(default_factory=dict)
    # Packets whose length is a statistical outlier for their host (z-score based).
    volume_anomaly_hosts: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["host_statistics"] = {ip: host.to_dict() for ip, host in self.host_statistics.items()}
        return data


def _counter_to_pairs(counter: Counter, limit: int = 10) -> list[tuple[str, int]]:
    return [(str(key), int(count)) for key, count in counter.most_common(limit)]


def compute_statistics(
    records: Iterable[PacketRecord],
    flows: Optional[list[Flow]] = None,
    host_volume_zscore: float = 3.0,
) -> TrafficStatistics:
    """Compute aggregate statistics from packet records."""
    stats = TrafficStatistics()
    protocol_counter: Counter = Counter()
    transport_counter: Counter = Counter()
    ethertype_counter: Counter = Counter()
    src_counter: Counter = Counter()
    dst_counter: Counter = Counter()
    dst_port_counter: Counter = Counter()
    tcp_flags: Counter = Counter()
    dns_queries: Counter = Counter()
    parse_statuses: Counter = Counter()
    hosts: dict[str, HostStatistics] = {}
    host_dst_ports: dict[str, set] = defaultdict(set)
    host_dst_ips: dict[str, set] = defaultdict(set)
    host_bytes: dict[str, int] = defaultdict(int)

    for record in records:
        stats.total_packets += 1
        stats.total_bytes += record.captured_length
        parse_statuses[record.parse_status] += 1

        if stats.first_timestamp is None or record.timestamp < stats.first_timestamp:
            stats.first_timestamp = record.timestamp
        if stats.last_timestamp is None or record.timestamp > stats.last_timestamp:
            stats.last_timestamp = record.timestamp

        for protocol in record.protocols:
            protocol_counter[protocol] += 1
        if record.transport_protocol:
            transport_counter[record.transport_protocol] += 1
        if record.eth_type is not None:
            ethertype_counter[f"0x{record.eth_type:04x}"] += 1

        if record.src_ip:
            src_counter[record.src_ip] += 1
            host = hosts.setdefault(record.src_ip, HostStatistics(ip=record.src_ip))
            host.packets_sent += 1
            host.bytes_sent += record.captured_length
            host_bytes[record.src_ip] += record.captured_length
            if record.dst_port is not None:
                host_dst_ports[record.src_ip].add(record.dst_port)
            if record.dst_ip:
                host_dst_ips[record.src_ip].add(record.dst_ip)
        if record.dst_ip:
            dst_counter[record.dst_ip] += 1
            host = hosts.setdefault(record.dst_ip, HostStatistics(ip=record.dst_ip))
            host.packets_received += 1
            host.bytes_received += record.captured_length
            host_bytes[record.dst_ip] += record.captured_length

        if record.dst_port is not None:
            dst_port_counter[str(record.dst_port)] += 1

        if record.tcp_flags:
            for flag in record.tcp_flags.split(","):
                flag = flag.strip()
                if flag:
                    tcp_flags[flag] += 1

        if record.dns_query:
            if record.dns_is_response:
                stats.dns_response_count += 1
            else:
                # Count queries only, so the "top queries" list reflects what was asked.
                dns_queries[record.dns_query] += 1
                stats.dns_query_count += 1
            if record.dns_rcode == "NXDOMAIN":
                stats.dns_nxdomain_count += 1

    for ip, host in hosts.items():
        host.distinct_dst_ports = len(host_dst_ports.get(ip, ()))
        host.distinct_dst_ips = len(host_dst_ips.get(ip, ()))

    stats.protocol_counts = dict(protocol_counter.most_common())
    stats.transport_counts = dict(transport_counter.most_common())
    stats.ethertype_counts = dict(ethertype_counter.most_common())
    stats.top_src_ips = _counter_to_pairs(src_counter)
    stats.top_dst_ips = _counter_to_pairs(dst_counter)
    stats.top_dst_ports = _counter_to_pairs(dst_port_counter)
    stats.tcp_flag_totals = dict(tcp_flags.most_common())
    stats.dns_top_queries = _counter_to_pairs(dns_queries)
    stats.parse_status_counts = dict(parse_statuses)
    stats.host_statistics = hosts

    if stats.first_timestamp is not None and stats.last_timestamp is not None:
        stats.duration_seconds = max(0.0, stats.last_timestamp - stats.first_timestamp)
    if stats.duration_seconds > 0:
        stats.packets_per_second = round(stats.total_packets / stats.duration_seconds, 4)
        stats.bytes_per_second = round(stats.total_bytes / stats.duration_seconds, 4)

    stats.volume_anomaly_hosts = _detect_host_volume_anomalies(host_bytes, host_volume_zscore)

    return stats


def _detect_host_volume_anomalies(
    host_bytes: dict[str, int], zscore_threshold: float
) -> list[dict[str, Any]]:
    """Flag hosts whose byte volume is a statistical outlier.

    Requires at least 4 hosts and non-zero variance; with fewer hosts the
    distribution is too small for the test to mean anything, so it returns
    nothing rather than reporting noise as an anomaly.
    """
    if len(host_bytes) < 4:
        return []
    values = list(host_bytes.values())
    mean = statistics.fmean(values)
    stdev = statistics.pstdev(values)
    if stdev == 0:
        return []

    anomalies: list[dict[str, Any]] = []
    for ip, value in sorted(host_bytes.items(), key=lambda item: item[1], reverse=True):
        zscore = (value - mean) / stdev
        if zscore >= zscore_threshold:
            anomalies.append(
                {
                    "ip": ip,
                    "bytes": value,
                    "mean_bytes": round(mean, 2),
                    "zscore": round(zscore, 4),
                    "note": (
                        "Byte volume is a statistical outlier within this capture only. "
                        "It is not evidence of malicious activity by itself."
                    ),
                }
            )
    return anomalies


def summarize_flow_statistics(flows: list[Flow]) -> dict[str, Any]:
    """Aggregate flow-level statistics for the report and AI summary."""
    if not flows:
        return {
            "flow_count": 0,
            "total_flow_packets": 0,
            "total_flow_bytes": 0,
            "tcp_flow_count": 0,
            "udp_flow_count": 0,
            "syn_only_flows": 0,
            "top_flows_by_bytes": [],
        }

    tcp_flows = [f for f in flows if f.transport_protocol == "TCP"]
    udp_flows = [f for f in flows if f.transport_protocol == "UDP"]
    top = sorted(flows, key=lambda f: f.total_bytes, reverse=True)[:10]

    return {
        "flow_count": len(flows),
        "total_flow_packets": sum(f.total_packets for f in flows),
        "total_flow_bytes": sum(f.total_bytes for f in flows),
        "tcp_flow_count": len(tcp_flows),
        "udp_flow_count": len(udp_flows),
        "syn_only_flows": sum(1 for f in tcp_flows if f.is_syn_only),
        "top_flows_by_bytes": [
            {
                "flow_id": f.flow_id,
                "src": f"{f.src_ip}:{f.src_port}" if f.src_port else f.src_ip,
                "dst": f"{f.dst_ip}:{f.dst_port}" if f.dst_port else f.dst_ip,
                "protocol": f.transport_protocol,
                "packets": f.total_packets,
                "bytes": f.total_bytes,
                "duration_seconds": round(f.duration, 6),
            }
            for f in top
        ],
    }
