"""Rule engine tests.

Two properties matter most here:

1. A rule fires when its condition is met.
2. A rule stays silent when its condition is not met -- no false positives on
   ordinary traffic.
"""

from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether

from scapy_ai_analyzer.analysis.flow_analyzer import analyze_flows
from scapy_ai_analyzer.analysis.rule_engine import (
    ALL_RULES,
    RuleEngine,
    build_rule_context,
)
from scapy_ai_analyzer.analysis.statistics import compute_statistics
from scapy_ai_analyzer.config import AnalysisConfig
from scapy_ai_analyzer.parsing.packet_parser import parse_packet


def _context(packets, config=None):
    records = [
        parse_packet(p, packet_id=index + 1, source_type="file")
        for index, p in enumerate(packets)
    ]
    flows = analyze_flows(records).flows
    stats = compute_statistics(records, flows)
    return build_rule_context(records, flows, stats, config or AnalysisConfig())


def _tcp(src, dst, sport, dport, flags, t, pad=0):
    packet = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if pad:
        from scapy.packet import Raw

        packet = packet / Raw(load=b"x" * pad)
    packet.time = 1700000000.0 + t
    return packet


def _dns_query(src, dst, qname, t):
    packet = (
        Ether()
        / IP(src=src, dst=dst)
        / UDP(sport=51000, dport=53)
        / DNS(id=1, rd=1, qd=DNSQR(qname=qname, qtype="A"))
    )
    packet.time = 1700000000.0 + t
    return packet


def _alerts_for(packets, rule_id, config=None):
    alerts = RuleEngine().evaluate(_context(packets, config))
    return [a for a in alerts if a.rule_id == rule_id]


class TestPortScanRule:
    def test_fires_on_many_distinct_ports(self):
        packets = [_tcp("192.0.2.1", "198.51.100.9", 40000 + i, 20 + i, "S", i * 0.05) for i in range(30)]
        alerts = _alerts_for(packets, "R001")
        assert alerts
        assert alerts[0].severity == "medium"
        assert alerts[0].metrics["distinct_dst_ports"] >= 15
        assert alerts[0].evidence_refs
        assert alerts[0].limitations

    def test_silent_on_same_port_repeatedly(self):
        """Repeated connections to one port are not port scanning."""
        packets = [_tcp("192.0.2.1", "198.51.100.9", 40000 + i, 443, "S", i * 0.05) for i in range(40)]
        assert _alerts_for(packets, "R001") == []

    def test_silent_below_threshold(self):
        packets = [_tcp("192.0.2.1", "198.51.100.9", 40000 + i, 20 + i, "S", i * 0.05) for i in range(5)]
        assert _alerts_for(packets, "R001") == []

    def test_silent_when_activity_spread_beyond_window(self):
        """Ports spread over hours must not trip a 60-second window."""
        packets = [
            _tcp("192.0.2.1", "198.51.100.9", 40000 + i, 20 + i, "S", i * 120.0)
            for i in range(30)
        ]
        assert _alerts_for(packets, "R001") == []

    def test_ignores_syn_ack_replies(self):
        """A server answering many clients is not a scanner."""
        packets = []
        for i in range(30):
            packets.append(_tcp("198.51.100.9", "192.0.2.1", 80, 40000 + i, "SA", i * 0.05))
        assert _alerts_for(packets, "R001") == []

    def test_ignores_udp_dns_responses(self):
        """DNS responses from a resolver must not look like UDP port fan-out."""
        packets = []
        for i in range(40):
            packet = (
                Ether()
                / IP(src="198.51.100.53", dst="192.0.2.1")
                / UDP(sport=53, dport=51000 + i)
                / DNS(id=i, qr=1, qd=DNSQR(qname="a.test"))
            )
            packet.time = 1700000000.0 + i * 0.01
            packets.append(packet)
        assert _alerts_for(packets, "R001") == []

    def test_window_restarts_so_long_scans_yield_separate_alerts(self):
        packets = [_tcp("192.0.2.1", "198.51.100.9", 40000 + i, 20 + i, "S", i * 0.05) for i in range(60)]
        alerts = _alerts_for(packets, "R001")
        assert len(alerts) >= 2

    def test_alert_includes_reason_and_evidence(self):
        packets = [_tcp("192.0.2.1", "198.51.100.9", 40000 + i, 20 + i, "S", i * 0.05) for i in range(30)]
        alert = _alerts_for(packets, "R001")[0]
        assert "distinct destination ports" in alert.reason
        assert "threshold" in alert.reason
        assert alert.packet_ids
        assert all(ref.startswith("packet-") for ref in alert.evidence_refs)


class TestFanoutRule:
    def test_fires_on_many_destinations(self):
        packets = [
            _tcp("192.0.2.1", f"198.51.100.{i % 250 + 1}", 40000, 443, "S", i * 0.01)
            for i in range(60)
        ]
        alerts = _alerts_for(packets, "R002")
        assert alerts
        assert alerts[0].metrics["distinct_destinations"] >= 30

    def test_silent_on_single_destination(self):
        packets = [_tcp("192.0.2.1", "198.51.100.1", 40000, 443, "S", i * 0.01) for i in range(60)]
        assert _alerts_for(packets, "R002") == []


class TestDnsRules:
    def test_dns_volume_fires(self):
        packets = [_dns_query("192.0.2.1", "198.51.100.53", f"h{i}.test", i * 0.01) for i in range(60)]
        alerts = _alerts_for(packets, "R003")
        assert alerts
        assert alerts[0].metrics["queries_in_window"] >= 50

    def test_dns_volume_silent_below_threshold(self):
        packets = [_dns_query("192.0.2.1", "198.51.100.53", f"h{i}.test", i * 0.01) for i in range(5)]
        assert _alerts_for(packets, "R003") == []

    def test_nxdomain_ratio_fires(self):
        packets = []
        for i in range(20):
            packets.append(_dns_query("192.0.2.1", "198.51.100.53", f"h{i}.test", i * 0.1))
            response = (
                Ether()
                / IP(src="198.51.100.53", dst="192.0.2.1")
                / UDP(sport=53, dport=51000)
                / DNS(id=i, qr=1, rcode=3, qd=DNSQR(qname=f"h{i}.test"))
            )
            response.time = 1700000000.0 + i * 0.1 + 0.01
            packets.append(response)
        alerts = _alerts_for(packets, "R004")
        assert alerts
        assert alerts[0].metrics["nxdomain_ratio"] == 1.0

    def test_nxdomain_silent_when_responses_are_ok(self):
        from scapy.layers.dns import DNSRR

        packets = []
        for i in range(20):
            response = (
                Ether()
                / IP(src="198.51.100.53", dst="192.0.2.1")
                / UDP(sport=53, dport=51000)
                / DNS(
                    id=i,
                    qr=1,
                    qd=DNSQR(qname=f"h{i}.test"),
                    an=DNSRR(rrname=f"h{i}.test", type="A", rdata="203.0.113.1"),
                )
            )
            response.time = 1700000000.0 + i * 0.1
            packets.append(response)
        assert _alerts_for(packets, "R004") == []


class TestHandshakeRule:
    def test_fires_on_syn_only_flows(self):
        packets = [_tcp("192.0.2.1", f"198.51.100.{i + 1}", 40000 + i, 80, "S", i * 0.01) for i in range(8)]
        alerts = _alerts_for(packets, "R005")
        assert alerts
        assert alerts[0].metrics["syn_only_flow_count"] == 8
        assert any(ref.startswith("flow-") for ref in alerts[0].evidence_refs)

    def test_silent_on_completed_handshakes(self):
        packets = []
        for i in range(8):
            packets.append(_tcp("192.0.2.1", "198.51.100.1", 40000 + i, 80, "S", i * 1.0))
            packets.append(_tcp("198.51.100.1", "192.0.2.1", 80, 40000 + i, "SA", i * 1.0 + 0.01))
            packets.append(_tcp("192.0.2.1", "198.51.100.1", 40000 + i, 80, "A", i * 1.0 + 0.02))
        assert _alerts_for(packets, "R005") == []

    def test_silent_with_too_few_flows(self):
        packets = [_tcp("192.0.2.1", "198.51.100.1", 40000, 80, "S", 0.0)]
        assert _alerts_for(packets, "R005") == []


class TestOtherRules:
    def test_malformed_rule_reports_partial_parses(self):
        packet = Ether(type=0x9000)
        packet.time = 1700000000.0
        alerts = _alerts_for([packet], "R006")
        assert alerts
        assert alerts[0].severity == "info"
        assert "not a security indicator" in " ".join(alerts[0].limitations)

    def test_malformed_rule_silent_on_clean_capture(self):
        packets = [_tcp("192.0.2.1", "198.51.100.1", 40000, 443, "S", 0.0)]
        assert _alerts_for(packets, "R006") == []

    def test_tcp_reset_rule(self):
        packets = [_tcp("192.0.2.1", "198.51.100.1", 40000 + i, 80 + i, "R", i * 0.01) for i in range(40)]
        alerts = _alerts_for(packets, "R008")
        assert alerts
        assert alerts[0].metrics["rst_count"] == 40

    def test_icmp_rule(self):
        packets = []
        for i in range(200):
            packet = Ether() / IP(src="192.0.2.1", dst="198.51.100.1") / ICMP(type=8, id=i)
            packet.time = 1700000000.0 + i * 0.001
            packets.append(packet)
        alerts = _alerts_for(packets, "R009")
        assert alerts

    def test_icmp_rule_silent_on_a_few_pings(self):
        packets = []
        for i in range(5):
            packet = Ether() / IP(src="192.0.2.1", dst="198.51.100.1") / ICMP(type=8, id=i)
            packet.time = 1700000000.0 + i
            packets.append(packet)
        assert _alerts_for(packets, "R009") == []


class TestEngineBehaviour:
    def test_all_rules_have_metadata_and_limitations(self):
        for rule in ALL_RULES:
            definition = rule.definition
            assert definition.rule_id.startswith("R")
            assert definition.name
            assert definition.description
            assert definition.severity in ("info", "low", "medium", "high", "critical")
            assert definition.limitations, f"{definition.rule_id} has no stated limitations"

    def test_rule_ids_are_unique(self):
        ids = [rule.definition.rule_id for rule in ALL_RULES]
        assert len(ids) == len(set(ids))

    def test_alerts_are_sorted_and_renumbered(self):
        packets = [_tcp("192.0.2.1", f"198.51.100.{i + 1}", 40000 + i, 20 + i, "S", i * 0.05) for i in range(40)]
        alerts = RuleEngine().evaluate(_context(packets))
        assert alerts
        timestamps = [a.timestamp for a in alerts]
        assert timestamps == sorted(timestamps)
        assert [a.alert_id for a in alerts] == [f"alert-{i:04d}" for i in range(1, len(alerts) + 1)]

    def test_clean_capture_produces_no_alerts(self):
        """Ordinary completed connections must not trip any rule."""
        packets = []
        for i in range(10):
            packets.append(_tcp("192.0.2.1", "198.51.100.1", 40000 + i, 443, "S", i * 1.0))
            packets.append(_tcp("198.51.100.1", "192.0.2.1", 443, 40000 + i, "SA", i * 1.0 + 0.01))
            packets.append(_tcp("192.0.2.1", "198.51.100.1", 40000 + i, 443, "A", i * 1.0 + 0.02))
            packets.append(_tcp("192.0.2.1", "198.51.100.1", 40000 + i, 443, "FA", i * 1.0 + 0.03))
            packets.append(_tcp("198.51.100.1", "192.0.2.1", 443, 40000 + i, "FA", i * 1.0 + 0.04))
        alerts = RuleEngine().evaluate(_context(packets))
        assert alerts == [], f"unexpected alerts: {[a.rule_id for a in alerts]}"

    def test_rule_failure_is_contained(self):
        """A rule that raises must not stop the engine or lose other results."""

        class BrokenRule:
            from scapy_ai_analyzer.analysis.rule_engine import RuleDefinition

            definition = RuleDefinition(
                rule_id="R999",
                name="Broken rule",
                severity="info",
                description="Always raises.",
                limitations=["Never produces a real result."],
            )

            def evaluate(self, context):
                raise RuntimeError("boom")

        engine = RuleEngine(rules=[BrokenRule()])
        alerts = engine.evaluate(_context([]))
        assert len(alerts) == 1
        assert "boom" in alerts[0].reason

    def test_thresholds_are_configurable(self):
        config = AnalysisConfig(scan_min_distinct_ports=3, scan_min_flows=3)
        packets = [_tcp("192.0.2.1", "198.51.100.9", 40000 + i, 20 + i, "S", i * 0.05) for i in range(4)]
        assert _alerts_for(packets, "R001", config)
