"""Report generation tests."""

from __future__ import annotations

import html
import json
from pathlib import Path

import pytest

from scapy_ai_analyzer.models.session import AnalysisSession, new_session_id, utc_now_iso
from scapy_ai_analyzer.reports.html_report import render_html, write_html_report
from scapy_ai_analyzer.reports.json_report import (
    read_json_report,
    render_json,
    write_json_report,
)


def _session_with_alerts() -> AnalysisSession:
    return AnalysisSession(
        session_id="test-session",
        started_at=utc_now_iso(),
        source="test.pcap",
        source_type="file",
        capture_format="pcap",
        packet_count=3,
        statistics={
            "packet_totals": {
                "packets": 3,
                "bytes": 300,
                "duration_seconds": 1.5,
                "packets_per_second": 2.0,
            },
            "protocol_counts": {"IPv4": 3, "TCP": 3},
            "transport_counts": {"TCP": 3},
            "top_dst_ports": [["443", 3]],
            "top_src_ips": [["192.0.2.1", 3]],
            "tcp_flag_totals": {"SYN": 1, "ACK": 2},
            "parse_status_counts": {"ok": 3},
            "dns": {"queries": 1, "responses": 1, "nxdomain": 0, "top_queries": [["a.test", 1]]},
            "host_volume_outliers": [],
        },
        flows=[
            {
                "flow_id": "flow-0001",
                "src_ip": "192.0.2.1",
                "src_port": 40000,
                "dst_ip": "198.51.100.1",
                "dst_port": 443,
                "transport_protocol": "TCP",
                "total_packets": 3,
                "total_bytes": 300,
                "duration": 1.5,
                "tcp_flag_counts": {"SYN": 1, "ACK": 2},
            }
        ],
        alerts=[
            {
                "alert_id": "alert-0001",
                "rule_id": "R001",
                "rule_name": "Multiple destination ports contacted in a short window",
                "severity": "medium",
                "description": "Source 192.0.2.1 contacted 20 distinct destination ports.",
                "reason": "Observed 20 connection attempts (threshold: 15 ports).",
                "timestamp": 1700000000.0,
                "src_ip": "192.0.2.1",
                "dst_ports": [20, 21, 22],
                "evidence_refs": ["packet-1", "packet-2"],
                "metrics": {"distinct_dst_ports": 20},
                "limitations": ["Distinct ports alone do not establish intent."],
            }
        ],
        packets=[
            {
                "packet_id": 1,
                "timestamp": 1700000000.0,
                "captured_length": 100,
                "src_ip": "192.0.2.1",
                "dst_ip": "198.51.100.1",
                "src_port": 40000,
                "dst_port": 443,
                "transport_protocol": "TCP",
                "tcp_flags": "SYN",
                "protocols": ["Ethernet", "IPv4", "TCP"],
                "parse_status": "ok",
            }
        ],
        ai_analysis={
            "finding": {
                "analysis_summary": "A source contacted many ports.",
                "finding_type": "rule_indicator_review",
                "severity": "medium",
                "confidence": 0.6,
                "observations": ["One source contacted 20 ports"],
                "evidence_refs": ["alert-0001"],
                "alternative_explanations": ["Service discovery"],
                "limitations": ["Capture may be incomplete"],
                "recommended_next_steps": ["Review the referenced flows"],
                "provider": "mock",
                "model": "mock-deterministic-v1",
                "validation_status": "valid",
                "validation_warnings": [],
            },
            "provider": "mock",
            "model": "mock-deterministic-v1",
            "enabled": True,
            "succeeded": True,
            "duration_seconds": 0.01,
            "attempts": 1,
            "errors": [],
            "warnings": [],
            "confidence_disclaimer": "Confidence is a self-reported model estimate.",
        },
        errors=[],
        warnings=["1 packet had parse warnings."],
        limitations=["Analysis covers only this capture."],
        configuration={"ai": {"provider": "mock", "api_key": None}},
        environment={"python_version": "3.13"},
        evidence_summary={"packets_indexed": 3},
    )


class TestJsonReport:
    def test_render_is_valid_json(self):
        session = _session_with_alerts()
        parsed = json.loads(render_json(session))
        assert parsed["session_id"] == "test-session"
        assert parsed["packet_count"] == 3

    def test_round_trip(self, tmp_path: Path):
        session = _session_with_alerts()
        path = write_json_report(session, tmp_path)
        assert path.exists()
        loaded = read_json_report(path)
        assert loaded.session_id == session.session_id
        assert len(loaded.alerts) == len(session.alerts)
        assert loaded.ai_analysis["finding"]["finding_type"] == "rule_indicator_review"

    def test_provenance_legend_is_included(self):
        parsed = json.loads(render_json(_session_with_alerts()))
        assert "provenance_legend" in parsed
        assert "observed" in parsed["provenance_legend"]
        assert "ai_inferred" in parsed["provenance_legend"]

    def test_api_key_never_appears(self):
        session = _session_with_alerts()
        session.configuration = {"ai": {"provider": "openai_compatible", "api_key": None, "api_key_set": True}}
        text = render_json(session)
        assert "sk-" not in text


class TestHtmlReport:
    def test_render_produces_a_complete_document(self):
        rendered = render_html(_session_with_alerts())
        assert rendered.startswith("<!DOCTYPE html>")
        assert rendered.rstrip().endswith("</html>")
        assert "<title>" in rendered

    def test_write_and_read_back(self, tmp_path: Path):
        path = write_html_report(_session_with_alerts(), tmp_path)
        assert path.exists()
        content = path.read_text(encoding="utf-8")
        assert "Scapy AI Analyzer" in content

    def test_provenance_tags_present(self):
        rendered = render_html(_session_with_alerts())
        assert 'class="tag tag-observed"' in rendered
        assert 'class="tag tag-rule"' in rendered
        assert 'class="tag tag-ai"' in rendered
        assert 'class="tag tag-review"' in rendered

    def test_ai_section_is_separated_and_flagged(self):
        rendered = render_html(_session_with_alerts())
        assert "AI interpretation" in rendered
        assert "must be verified by a human" in rendered

    def test_alert_reason_and_limitations_are_shown(self):
        rendered = render_html(_session_with_alerts())
        assert "Why it fired" in rendered
        assert "Distinct ports alone do not establish intent" in rendered

    def test_untrusted_text_is_escaped(self):
        """Packet-derived text must never be inserted as raw HTML."""
        session = _session_with_alerts()
        session.alerts[0]["description"] = '<script>alert("xss")</script>'
        session.alerts[0]["rule_name"] = '<img src=x onerror=alert(1)>'
        rendered = render_html(session)
        # No executable tag survives: every injected '<' is escaped.
        assert "<script>alert" not in rendered
        assert "<img src=x" not in rendered
        assert "&lt;script&gt;" in rendered
        assert "&lt;img src=x" in rendered

    def test_ai_output_is_escaped(self):
        session = _session_with_alerts()
        session.ai_analysis["finding"]["analysis_summary"] = "<script>bad()</script>"
        rendered = render_html(session)
        assert "<script>bad()" not in rendered
        assert "&lt;script&gt;" in rendered

    def test_evidence_references_are_rendered(self):
        rendered = render_html(_session_with_alerts())
        assert "alert-0001" in rendered

    def test_ai_disabled_state_is_explained(self):
        session = _session_with_alerts()
        session.ai_analysis = {
            "finding": {
                "analysis_summary": "AI disabled.",
                "finding_type": "ai_unavailable",
                "severity": "info",
                "confidence": None,
                "evidence_refs": [],
                "validation_status": "rejected",
                "validation_warnings": ["ai_disabled"],
            },
            "provider": "mock",
            "enabled": False,
            "succeeded": False,
            "errors": ["ai_disabled"],
            "warnings": [],
        }
        rendered = render_html(session)
        assert "disabled for this run" in rendered
        assert "remain valid" in rendered

    def test_no_ai_section_when_not_run(self):
        session = _session_with_alerts()
        session.ai_analysis = None
        rendered = render_html(session)
        assert "AI analysis was not run" in rendered

    def test_failed_ai_is_reported_without_losing_deterministic_results(self):
        session = _session_with_alerts()
        session.ai_analysis["succeeded"] = False
        session.ai_analysis["errors"] = ["Provider request timed out."]
        session.ai_analysis["finding"]["validation_status"] = "rejected"
        rendered = render_html(session)
        assert "did not produce a validated finding" in rendered
        # Rule alerts are still present.
        assert "alert-0001" in rendered

    def test_empty_session_renders(self):
        session = AnalysisSession(
            session_id="empty",
            started_at=utc_now_iso(),
            source="none.pcap",
            source_type="file",
        )
        rendered = render_html(session)
        assert "No flows were formed" in rendered
        assert "No rule alerts were raised" in rendered

    def test_unicode_content_is_preserved(self):
        session = _session_with_alerts()
        session.alerts[0]["description"] = "تحليل حركة الشبكة"
        rendered = render_html(session)
        assert "تحليل حركة الشبكة" in rendered
