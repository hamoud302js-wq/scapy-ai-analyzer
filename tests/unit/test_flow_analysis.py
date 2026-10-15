"""Flow grouping and statistics tests."""

from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from scapy_ai_analyzer.analysis.flow_analyzer import (
    FlowAnalyzer,
    analyze_flows,
    compute_flow_direction_stats,
)
from scapy_ai_analyzer.analysis.statistics import compute_statistics, summarize_flow_statistics
from scapy_ai_analyzer.parsing.packet_parser import parse_packet


def _records(packets):
    return [
        parse_packet(p, packet_id=index + 1, source_type="file")
        for index, p in enumerate(packets)
    ]


def _tcp(src, dst, sport, dport, flags, time_offset=0.0, length_pad=0):
    packet = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if length_pad:
        from scapy.packet import Raw

        packet = packet / Raw(load=b"x" * length_pad)
    packet.time = 1700000000.0 + time_offset
    return packet


class TestFlowGrouping:
    def test_both_directions_form_one_flow(self):
        packets = [
            _tcp("192.0.2.1", "198.51.100.2", 40000, 443, "S", 0.0),
            _tcp("198.51.100.2", "192.0.2.1", 443, 40000, "SA", 0.1),
            _tcp("192.0.2.1", "198.51.100.2", 40000, 443, "A", 0.2),
        ]
        result = analyze_flows(_records(packets))
        assert len(result.flows) == 1
        flow = result.flows[0]
        assert flow.packet_count == 3
        assert flow.packets_forward + flow.packets_reverse == 3
        assert flow.total_packets == 3

    def test_different_conversations_are_separate_flows(self):
        packets = [
            _tcp("192.0.2.1", "198.51.100.2", 40000, 443, "S", 0.0),
            _tcp("192.0.2.1", "198.51.100.3", 40001, 443, "S", 0.1),
            _tcp("192.0.2.2", "198.51.100.2", 40002, 443, "S", 0.2),
        ]
        result = analyze_flows(_records(packets))
        assert len(result.flows) == 3

    def test_tcp_and_udp_same_port_pair_are_distinct(self):
        tcp_packet = _tcp("192.0.2.1", "198.51.100.2", 5000, 5000, "S", 0.0)
        udp_packet = Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / UDP(sport=5000, dport=5000)
        udp_packet.time = 1700000000.1

        result = analyze_flows(_records([tcp_packet, udp_packet]))
        assert len(result.flows) == 2
        protocols = {flow.transport_protocol for flow in result.flows}
        assert protocols == {"TCP", "UDP"}

    def test_idle_timeout_splits_reused_key(self):
        packets = [
            _tcp("192.0.2.1", "198.51.100.2", 40000, 443, "S", 0.0),
            _tcp("192.0.2.1", "198.51.100.2", 40000, 443, "A", 500.0),
        ]
        result = analyze_flows(_records(packets), idle_timeout=60.0)
        assert len(result.flows) == 2

    def test_packets_without_transport_are_reported_unassigned(self):
        arp = Ether() / IP(src="192.0.2.1", dst="198.51.100.2", proto=47)
        arp.time = 1700000000.0
        result = analyze_flows(_records([arp]))
        assert result.flows == []
        assert result.unassigned_packet_ids == [1]

    def test_flow_ids_are_stable_and_sequential(self):
        packets = [
            _tcp("192.0.2.1", "198.51.100.2", 1, 2, "S", 0.0),
            _tcp("192.0.2.1", "198.51.100.3", 1, 2, "S", 0.1),
        ]
        result = analyze_flows(_records(packets))
        assert [f.flow_id for f in result.flows] == ["flow-0001", "flow-0002"]

    def test_flow_key_is_direction_independent(self):
        from scapy_ai_analyzer.models.flow import make_flow_key

        forward = make_flow_key("192.0.2.1", "198.51.100.2", "TCP", 40000, 443)
        backward = make_flow_key("198.51.100.2", "192.0.2.1", "TCP", 443, 40000)
        assert forward == backward

    def test_flow_references_contributing_packets(self):
        packets = [
            _tcp("192.0.2.1", "198.51.100.2", 40000, 443, "S", 0.0),
            _tcp("192.0.2.1", "198.51.100.2", 40000, 443, "A", 0.1),
        ]
        result = analyze_flows(_records(packets))
        assert result.flows[0].packet_ids == [1, 2]

    def test_tcp_flag_counts_per_flow(self):
        packets = [
            _tcp("192.0.2.1", "198.51.100.2", 40000, 443, "S", 0.0),
            _tcp("198.51.100.2", "192.0.2.1", 443, 40000, "SA", 0.1),
            _tcp("192.0.2.1", "198.51.100.2", 40000, 443, "FA", 0.2),
        ]
        flow = analyze_flows(_records(packets)).flows[0]
        assert flow.tcp_flag_counts.get("SYN") == 2
        assert flow.tcp_flag_counts.get("ACK") == 2
        assert flow.tcp_flag_counts.get("FIN") == 1
        assert flow.is_syn_only is False

    def test_syn_only_flow_detection(self):
        flow = analyze_flows(_records([_tcp("192.0.2.1", "198.51.100.2", 40000, 443, "S", 0.0)])).flows[0]
        assert flow.is_syn_only is True

    def test_direction_stats(self):
        packets = [
            _tcp("192.0.2.1", "198.51.100.2", 40000, 443, "S", 0.0, length_pad=100),
            _tcp("198.51.100.2", "192.0.2.1", 443, 40000, "SA", 0.5),
        ]
        flow = analyze_flows(_records(packets)).flows[0]
        stats = compute_flow_direction_stats(flow)
        assert stats["bytes_forward"] > stats["bytes_reverse"]
        assert stats["duration_seconds"] == 0.5
        assert 0.0 <= stats["bytes_forward_ratio"] <= 1.0


class TestStatistics:
    def test_protocol_and_transport_counts(self):
        packets = [
            _tcp("192.0.2.1", "198.51.100.2", 40000, 443, "S", 0.0),
            Ether() / IP(src="192.0.2.1", dst="198.51.100.2") / UDP(sport=1, dport=53),
        ]
        packets[1].time = 1700000001.0
        stats = compute_statistics(_records(packets))
        assert stats.total_packets == 2
        assert stats.transport_counts.get("TCP") == 1
        assert stats.transport_counts.get("UDP") == 1
        assert stats.protocol_counts.get("IPv4") == 2

    def test_dns_counters(self):
        query = (
            Ether()
            / IP(src="192.0.2.1", dst="198.51.100.2")
            / UDP(sport=51000, dport=53)
            / DNS(id=1, rd=1, qd=DNSQR(qname="a.test"))
        )
        query.time = 1700000000.0
        stats = compute_statistics(_records([query]))
        assert stats.dns_query_count == 1
        assert stats.dns_response_count == 0
        assert stats.dns_top_queries == [("a.test", 1)]

    def test_timestamps_and_duration(self):
        packets = [
            _tcp("192.0.2.1", "198.51.100.2", 1, 2, "S", 0.0),
            _tcp("192.0.2.1", "198.51.100.2", 1, 2, "A", 10.0),
        ]
        stats = compute_statistics(_records(packets))
        assert stats.first_timestamp == 1700000000.0
        assert stats.last_timestamp == 1700000010.0
        assert stats.duration_seconds == 10.0
        assert stats.packets_per_second == 0.2

    def test_parse_status_counted(self):
        from scapy.layers.l2 import Ether as E

        bad = E(type=0x9000)
        bad.time = 1700000000.0
        stats = compute_statistics(_records([bad]))
        assert "partial" in stats.parse_status_counts

    def test_volume_anomaly_requires_enough_hosts(self):
        """With too few hosts the test is meaningless, so nothing is reported."""
        packets = [
            _tcp("192.0.2.1", "198.51.100.2", 1, 2, "S", 0.0, length_pad=1000),
            _tcp("192.0.2.2", "198.51.100.2", 1, 2, "S", 0.1),
        ]
        stats = compute_statistics(_records(packets))
        assert stats.volume_anomaly_hosts == []

    def test_volume_anomaly_detects_outlier_with_enough_hosts(self):
        # With n hosts the maximum attainable z-score is sqrt(n-1), so a
        # threshold of 3.0 requires at least 10 hosts to be reachable at all.
        # Each source has its own destination so that a shared destination does
        # not aggregate all traffic and mask the outlier source.
        packets = []
        for index in range(12):
            packets.append(
                _tcp(
                    f"192.0.2.{index + 1}",
                    f"198.51.100.{index + 1}",
                    1,
                    2,
                    "S",
                    index * 0.1,
                    length_pad=200,
                )
            )
        for index in range(60):
            packets.append(
                _tcp("192.0.2.1", "198.51.100.1", 1, 2, "A", 10 + index * 0.01, length_pad=800)
            )
        stats = compute_statistics(_records(packets))
        assert stats.volume_anomaly_hosts
        anomalous_hosts = {entry["ip"] for entry in stats.volume_anomaly_hosts}
        assert "192.0.2.1" in anomalous_hosts
        assert all(
            "not evidence of malicious activity" in entry["note"]
            for entry in stats.volume_anomaly_hosts
        )

    def test_volume_anomaly_is_unreachable_with_too_few_hosts(self):
        """A single outlier among few hosts cannot reach a z-score of 3.

        This documents a real limitation of the test: the maximum possible
        z-score for n observations is sqrt(n-1).
        """
        packets = [
            _tcp("192.0.2.1", "198.51.100.2", 1, 2, "S", 0.0, length_pad=5000),
            _tcp("192.0.2.2", "198.51.100.2", 1, 2, "S", 0.1),
            _tcp("192.0.2.3", "198.51.100.2", 1, 2, "S", 0.2),
            _tcp("192.0.2.4", "198.51.100.2", 1, 2, "S", 0.3),
        ]
        stats = compute_statistics(_records(packets))
        assert stats.volume_anomaly_hosts == []

    def test_summarize_flow_statistics_empty(self):
        summary = summarize_flow_statistics([])
        assert summary["flow_count"] == 0
        assert summary["top_flows_by_bytes"] == []

    def test_summarize_flow_statistics_counts(self):
        packets = [
            _tcp("192.0.2.1", "198.51.100.2", 40000, 443, "S", 0.0),
            _tcp("192.0.2.1", "198.51.100.3", 40001, 80, "S", 0.1),
        ]
        flows = analyze_flows(_records(packets)).flows
        summary = summarize_flow_statistics(flows)
        assert summary["flow_count"] == 2
        assert summary["tcp_flow_count"] == 2
        assert summary["syn_only_flows"] == 2
