"""Flow (conversation) analysis.

Packets are grouped into bidirectional flows keyed by endpoints and transport
protocol. An idle timeout splits a long-lived key into separate flows so that a
reused port pair does not merge unrelated conversations.

Direction handling: the flow key is canonical (endpoints sorted), so the same
conversation maps to one flow whichever side spoke first. Per-direction counters
are derived by comparing each packet against the flow's canonical source.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from ..models.flow import Flow, make_flow_key
from ..models.packet import PacketRecord


@dataclass
class FlowAnalysisResult:
    flows: list[Flow] = field(default_factory=list)
    # Packets that could not be assigned to a flow (no IP or no transport).
    unassigned_packet_ids: list[int] = field(default_factory=list)


class FlowAnalyzer:
    """Incremental flow builder.

    Records are fed in capture order. Flows are emitted when they go idle for
    longer than ``idle_timeout``, and any remaining flows are emitted by
    :meth:`finish`.
    """

    def __init__(self, idle_timeout: float = 120.0) -> None:
        if idle_timeout <= 0:
            raise ValueError("idle_timeout must be greater than 0.")
        self.idle_timeout = idle_timeout
        self._active: dict[tuple, Flow] = {}
        self._last_seen: dict[tuple, float] = {}
        self._completed: list[Flow] = []
        self._flow_counter = 0
        self._unassigned: list[int] = []

    def add_packet(self, record: PacketRecord) -> Optional[Flow]:
        """Assign one packet to a flow. Returns the flow when it was completed."""
        key = self._flow_key_for(record)
        if key is None:
            self._unassigned.append(record.packet_id)
            return None

        completed: Optional[Flow] = None
        existing = self._active.get(key)
        if existing is not None:
            last_seen = self._last_seen.get(key, existing.end_time)
            if record.timestamp - last_seen > self.idle_timeout:
                completed = existing
                self._finalize(completed)
                self._active.pop(key, None)
                self._last_seen.pop(key, None)
                existing = None

        if existing is None:
            existing = self._create_flow(key, record)
            self._active[key] = existing

        self._update_flow(existing, record)
        self._last_seen[key] = max(record.timestamp, existing.end_time)
        return completed

    def finish(self) -> FlowAnalysisResult:
        """Flush remaining active flows and return the full result."""
        for key, flow in list(self._active.items()):
            self._finalize(flow)
            self._active.pop(key, None)
            self._last_seen.pop(key, None)
        flows = sorted(self._completed, key=lambda f: (f.start_time, f.flow_id))
        return FlowAnalysisResult(flows=flows, unassigned_packet_ids=list(self._unassigned))

    def _flow_key_for(self, record: PacketRecord) -> Optional[tuple]:
        if not record.src_ip or not record.dst_ip:
            return None
        if record.transport_protocol is None:
            return None
        return make_flow_key(
            record.src_ip,
            record.dst_ip,
            record.transport_protocol,
            record.src_port,
            record.dst_port,
        )

    def _create_flow(self, key: tuple, record: PacketRecord) -> Flow:
        self._flow_counter += 1
        flow = Flow(
            flow_id=f"flow-{self._flow_counter:04d}",
            src_ip=key[0],
            dst_ip=key[1],
            src_port=None if key[2] == -1 else key[2],
            dst_port=None if key[3] == -1 else key[3],
            transport_protocol=key[4],
            start_time=record.timestamp,
            end_time=record.timestamp,
        )
        return flow

    def _update_flow(self, flow: Flow, record: PacketRecord) -> None:
        flow.packet_count += 1
        flow.start_time = min(flow.start_time, record.timestamp)
        flow.end_time = max(flow.end_time, record.timestamp)
        flow.packet_ids.append(record.packet_id)

        # Forward means the packet travels from the flow's canonical source.
        is_forward = record.src_ip == flow.src_ip and (
            record.src_port is None or flow.src_port is None or record.src_port == flow.src_port
        )
        if is_forward:
            flow.packets_forward += 1
            flow.bytes_forward += record.captured_length
        else:
            flow.packets_reverse += 1
            flow.bytes_reverse += record.captured_length

        if record.tcp_flags:
            for flag in record.tcp_flags.split(","):
                flag = flag.strip()
                if flag:
                    flow.tcp_flag_counts[flag] = flow.tcp_flag_counts.get(flag, 0) + 1

        if record.dns_query:
            flow.dns_query_count += 1
            if record.dns_query not in flow.dns_queries:
                flow.dns_queries.append(record.dns_query)

        if record.http_host and record.http_host not in flow.http_hosts:
            flow.http_hosts.append(record.http_host)

        if record.tls_sni and record.tls_sni not in flow.tls_snis:
            flow.tls_snis.append(record.tls_sni)

    def _finalize(self, flow: Flow) -> None:
        self._completed.append(flow)


def analyze_flows(records: Iterable[PacketRecord], idle_timeout: float = 120.0) -> FlowAnalysisResult:
    """Convenience wrapper: build flows from an iterable of records."""
    analyzer = FlowAnalyzer(idle_timeout=idle_timeout)
    for record in records:
        analyzer.add_packet(record)
    return analyzer.finish()


def compute_flow_direction_stats(flow: Flow) -> dict[str, float]:
    """Return derived directional metrics for a flow."""
    total_bytes = flow.total_bytes
    total_packets = flow.total_packets
    return {
        "duration_seconds": round(flow.duration, 6),
        "packets_forward": flow.packets_forward,
        "packets_reverse": flow.packets_reverse,
        "bytes_forward": flow.bytes_forward,
        "bytes_reverse": flow.bytes_reverse,
        "bytes_forward_ratio": round(flow.bytes_forward / total_bytes, 4) if total_bytes else 0.0,
        "packets_forward_ratio": round(flow.packets_forward / total_packets, 4)
        if total_packets
        else 0.0,
        "packets_per_second": round(total_packets / flow.duration, 4) if flow.duration > 0 else 0.0,
    }
