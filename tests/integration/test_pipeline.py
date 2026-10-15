"""End-to-end integration tests.

These exercise the complete chain on generated captures:

    read -> parse -> normalize -> flows -> statistics -> rules -> AI -> report

They run fully offline with the mock provider, so no API key is required.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scapy_ai_analyzer.ai.providers.mock_provider import MockProvider
from scapy_ai_analyzer.ai.service import AIService
from scapy_ai_analyzer.config import AIConfig, AppConfig
from scapy_ai_analyzer.pipeline import Pipeline
from scapy_ai_analyzer.reports.html_report import write_html_report
from scapy_ai_analyzer.reports.json_report import read_json_report, write_json_report


def _pipeline(tmp_path: Path, ai_enabled: bool = True, provider=None) -> Pipeline:
    config = AppConfig()
    config.report.output_dir = str(tmp_path / "results")
    config.ai = AIConfig(enabled=ai_enabled, provider="mock")
    service = AIService(config.ai, provider=provider or MockProvider())
    return Pipeline(config, ai_service=service)


class TestFullChain:
    def test_basic_capture_end_to_end(self, basic_pcap: Path, tmp_path: Path):
        result = _pipeline(tmp_path).run_file(str(basic_pcap))
        session = result.session

        assert session.packet_count > 0
        assert session.source == str(basic_pcap)
        assert session.capture_format == "pcap"
        assert session.flows
        assert session.statistics["packet_totals"]["packets"] == session.packet_count
        assert session.ai_analysis is not None
        assert session.ai_analysis["succeeded"] is True

    def test_all_protocol_families_are_extracted(self, basic_pcap: Path, tmp_path: Path):
        result = _pipeline(tmp_path).run_file(str(basic_pcap))
        protocols = set(result.session.statistics["protocol_counts"])
        assert {"Ethernet", "IPv4", "TCP", "UDP", "DNS", "ICMP", "IPv6", "ARP"} <= protocols
        assert "VLAN" in protocols
        assert "HTTP" in protocols

    def test_reports_are_written_and_readable(self, basic_pcap: Path, tmp_path: Path):
        result = _pipeline(tmp_path).run_file(str(basic_pcap))
        json_path = write_json_report(result.session, tmp_path / "out")
        html_path = write_html_report(result.session, tmp_path / "out")

        assert json_path.exists() and html_path.exists()
        loaded = read_json_report(json_path)
        assert loaded.session_id == result.session.session_id
        assert loaded.packet_count == result.session.packet_count

        html_text = html_path.read_text(encoding="utf-8")
        assert html_text.startswith("<!DOCTYPE html>")
        assert result.session.session_id in html_text

    def test_scan_capture_raises_scan_alert_with_evidence(self, scan_pcap: Path, tmp_path: Path):
        result = _pipeline(tmp_path).run_file(str(scan_pcap))
        scan_alerts = [a for a in result.alerts if a.rule_id == "R001"]
        assert scan_alerts
        alert = scan_alerts[0]
        assert alert.evidence_refs
        assert alert.limitations
        assert alert.metrics["distinct_dst_ports"] >= 15

    def test_dns_capture_raises_dns_alerts(self, dns_pcap: Path, tmp_path: Path):
        result = _pipeline(tmp_path).run_file(str(dns_pcap))
        rule_ids = {a.rule_id for a in result.alerts}
        assert "R003" in rule_ids
        assert "R004" in rule_ids

    def test_clean_capture_raises_no_alerts(self, clean_pcap: Path, tmp_path: Path):
        result = _pipeline(tmp_path).run_file(str(clean_pcap))
        assert result.alerts == []

    def test_every_ai_reference_resolves_to_evidence(self, scan_pcap: Path, tmp_path: Path):
        """The core guarantee: AI references must point at real evidence."""
        result = _pipeline(tmp_path).run_file(str(scan_pcap))
        finding_refs = result.ai_result.finding.evidence_refs

        valid_flow_ids = {f.flow_id for f in result.flows}
        valid_alert_ids = {a.alert_id for a in result.alerts}
        valid_packet_ids = {r.packet_id for r in result.records}

        for ref in finding_refs:
            if ref.startswith("flow-"):
                assert ref in valid_flow_ids, f"unknown flow reference {ref}"
            elif ref.startswith("alert-"):
                assert ref in valid_alert_ids, f"unknown alert reference {ref}"
            elif ref.startswith("packet-"):
                assert int(ref.removeprefix("packet-")) in valid_packet_ids

    def test_no_ai_mode_still_produces_complete_results(self, scan_pcap: Path, tmp_path: Path):
        result = _pipeline(tmp_path, ai_enabled=False).run_file(str(scan_pcap))
        session = result.session

        assert session.ai_analysis["enabled"] is False
        assert session.ai_analysis["succeeded"] is False
        # Deterministic results are intact.
        assert session.packet_count > 0
        assert session.flows
        assert session.alerts
        assert session.statistics["packet_totals"]["packets"] > 0

    def test_ai_failure_does_not_lose_deterministic_results(self, scan_pcap: Path, tmp_path: Path):
        pipeline = _pipeline(tmp_path, provider=MockProvider(fail_mode="malformed"))
        result = pipeline.run_file(str(scan_pcap))
        session = result.session

        assert session.ai_analysis["succeeded"] is False
        assert session.alerts
        assert session.flows
        assert any("AI analysis did not produce a validated finding" in w for w in session.warnings)

    def test_max_packets_limit_is_respected(self, scan_pcap: Path, tmp_path: Path):
        config = AppConfig()
        config.capture.max_packets = 10
        config.report.output_dir = str(tmp_path / "results")
        config.ai = AIConfig(enabled=False)
        result = Pipeline(config).run_file(str(scan_pcap))

        assert result.session.packet_count == 10
        assert any("max_packets" in w for w in result.session.warnings)

    def test_session_ids_are_unique(self, basic_pcap: Path, tmp_path: Path):
        first = _pipeline(tmp_path).run_file(str(basic_pcap)).session.session_id
        second = _pipeline(tmp_path).run_file(str(basic_pcap)).session.session_id
        assert first != second

    def test_configuration_is_recorded_without_secrets(self, basic_pcap: Path, tmp_path: Path):
        pipeline = _pipeline(tmp_path)
        pipeline.config.ai.api_key = "sk-secret-value-should-not-appear"
        result = pipeline.run_file(str(basic_pcap))
        serialized = json.dumps(result.session.to_dict())
        assert "sk-secret-value-should-not-appear" not in serialized

    def test_statistics_are_self_consistent(self, basic_pcap: Path, tmp_path: Path):
        result = _pipeline(tmp_path).run_file(str(basic_pcap))
        stats = result.session.statistics

        total = stats["packet_totals"]["packets"]
        assert sum(stats["parse_status_counts"].values()) == total
        assert sum(stats["transport_counts"].values()) <= total
        assert len(result.session.packets) == total

    def test_flow_packet_ids_reference_real_packets(self, basic_pcap: Path, tmp_path: Path):
        result = _pipeline(tmp_path).run_file(str(basic_pcap))
        packet_ids = {r.packet_id for r in result.records}
        for flow in result.flows:
            for packet_id in flow.packet_ids:
                assert packet_id in packet_ids

    def test_progress_callback_receives_stage_events(self, basic_pcap: Path, tmp_path: Path):
        events: list[str] = []
        config = AppConfig()
        config.report.output_dir = str(tmp_path / "results")
        config.ai = AIConfig(enabled=False)
        pipeline = Pipeline(config, progress=lambda event, data: events.append(event))
        pipeline.run_file(str(basic_pcap))

        assert "start" in events
        assert "progress" in events
        assert "flows" in events
        assert "rules" in events
        assert "complete" in events


class TestMissingData:
    def test_capture_missing_middle_packets_still_analyzes(self, tmp_path: Path):
        """A flow whose handshake is absent must not break analysis."""
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether
        from scapy.utils import wrpcap

        packets = []
        for index in range(5):
            packet = Ether() / IP(src="192.0.2.1", dst="198.51.100.1") / TCP(
                sport=40000, dport=443, flags="A", seq=1000 + index
            )
            packet.time = 1700000000.0 + index
            packets.append(packet)
        path = tmp_path / "no_handshake.pcap"
        wrpcap(str(path), packets)

        result = _pipeline(tmp_path).run_file(str(path))
        assert result.session.packet_count == 5
        assert result.flows
        # No SYN seen, so the SYN-only rule must not fire.
        assert all(a.rule_id != "R005" for a in result.alerts)

    def test_empty_capture_file_is_rejected_clearly(self, tmp_path: Path):
        from scapy_ai_analyzer.capture.file_reader import CaptureFileError

        path = tmp_path / "empty.pcap"
        path.write_bytes(b"")
        with pytest.raises(CaptureFileError, match="empty"):
            _pipeline(tmp_path).run_file(str(path))

    def test_missing_file_is_rejected_clearly(self, tmp_path: Path):
        from scapy_ai_analyzer.capture.file_reader import CaptureFileError

        with pytest.raises(CaptureFileError, match="not found"):
            _pipeline(tmp_path).run_file(str(tmp_path / "absent.pcap"))

    def test_unrecognized_format_is_rejected_clearly(self, tmp_path: Path):
        from scapy_ai_analyzer.capture.file_reader import CaptureFileError

        path = tmp_path / "notacapture.pcap"
        path.write_bytes(b"this is not a capture file at all")
        with pytest.raises(CaptureFileError, match="Unrecognized capture format"):
            _pipeline(tmp_path).run_file(str(path))

    def test_pcapng_is_supported(self, tmp_path: Path):
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether
        from scapy.utils import PcapNgWriter

        packet = Ether() / IP(src="192.0.2.1", dst="198.51.100.1") / TCP(sport=1, dport=2, flags="S")
        packet.time = 1700000000.0
        path = tmp_path / "capture.pcapng"
        writer = PcapNgWriter(str(path))
        writer.write(packet)
        writer.close()

        result = _pipeline(tmp_path).run_file(str(path))
        assert result.session.capture_format == "pcapng"
        assert result.session.packet_count == 1


class TestBatchStreaming:
    def test_small_batches_produce_same_result(self, scan_pcap: Path, tmp_path: Path):
        config_a = AppConfig()
        config_a.report.output_dir = str(tmp_path / "a")
        config_a.capture.batch_size = 5
        config_a.ai = AIConfig(enabled=False)

        config_b = AppConfig()
        config_b.report.output_dir = str(tmp_path / "b")
        config_b.capture.batch_size = 10000
        config_b.ai = AIConfig(enabled=False)

        small = Pipeline(config_a).run_file(str(scan_pcap))
        large = Pipeline(config_b).run_file(str(scan_pcap))

        assert small.session.packet_count == large.session.packet_count
        assert len(small.flows) == len(large.flows)
        assert len(small.alerts) == len(large.alerts)

    def test_read_stats_report_format(self, basic_pcap: Path, tmp_path: Path):
        result = _pipeline(tmp_path).run_file(str(basic_pcap))
        assert result.read_stats.capture_format == "pcap"
        assert result.read_stats.packets_read == result.session.packet_count
        assert result.read_stats.packets_failed == 0
