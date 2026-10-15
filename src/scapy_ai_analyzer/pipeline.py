"""Analysis pipeline.

Wires the stages together in a fixed order:

    source -> parse -> normalize -> flows -> statistics -> rules -> AI -> session

Each stage is a separate module and none of them call the AI layer except
:meth:`Pipeline.run_ai`. The deterministic stages run to completion before any
AI call is made, which is what allows ``--no-ai`` (or an AI failure) to leave a
complete, valid result.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from .ai.service import AIAnalysisResult, AIService
from .analysis.flow_analyzer import FlowAnalyzer
from .analysis.rule_engine import RuleEngine, build_rule_context
from .analysis.statistics import compute_statistics
from .capture.file_reader import ReadStats, iter_packet_batches
from .config import AppConfig
from .evidence.evidence_store import EvidenceStore
from .models.finding import Alert
from .models.flow import Flow
from .models.packet import PacketRecord
from .models.session import (
    AnalysisSession,
    environment_info,
    new_session_id,
    utc_now_iso,
)
from .parsing.normalizer import normalize_record, apply_privacy

TOOL_VERSION = "0.1.0"

# Cap on packets retained in memory for AI sampling and detailed reporting.
MAX_RETAINED_PACKETS = 200_000

DEFAULT_LIMITATIONS = [
    "Analysis covers only the packets present in this capture; activity outside it "
    "is not represented.",
    "Encrypted payload contents are not inspected; only metadata is analyzed.",
    "Rule thresholds are configurable and their output is an indicator, not a verdict.",
    "Statistical outliers are computed within this capture and are not a baseline "
    "comparison against historical behaviour.",
    "AI-generated interpretation is model output and requires human verification.",
]

ProgressCallback = Callable[[str, dict], None]


@dataclass
class PipelineResult:
    """Everything produced by one pipeline run."""

    session: AnalysisSession
    records: list[PacketRecord] = field(default_factory=list)
    flows: list[Flow] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    read_stats: Optional[ReadStats] = None
    ai_result: Optional[AIAnalysisResult] = None


class Pipeline:
    """Runs the full analysis chain for one capture source."""

    def __init__(
        self,
        config: AppConfig,
        progress: Optional[ProgressCallback] = None,
        ai_service: Optional[AIService] = None,
    ) -> None:
        self.config = config
        self.progress = progress or (lambda event, data: None)
        self.ai_service = ai_service
        self.rule_engine = RuleEngine()

    def _emit(self, event: str, **data) -> None:
        self.progress(event, data)

    # -- Stage 1-2: read and parse -------------------------------------------
    def read_source(self, source: str, source_type: str = "file") -> tuple[list[PacketRecord], ReadStats]:
        """Read packets from a file, normalizing as they stream in."""
        records: list[PacketRecord] = []
        stats: Optional[ReadStats] = None

        for batch, live_stats in iter_packet_batches(
            source,
            batch_size=self.config.capture.batch_size,
            max_packets=self.config.capture.max_packets,
            source_type=source_type,
        ):
            stats = live_stats
            for record in batch:
                normalized = normalize_record(record)
                normalized = apply_privacy(normalized, self.config.privacy)
                if len(records) < MAX_RETAINED_PACKETS:
                    records.append(normalized)
            self._emit(
                "progress",
                packets_read=stats.packets_read,
                packets_parsed=stats.packets_parsed,
                packets_failed=stats.packets_failed,
            )

        if stats is None:
            stats = ReadStats()
        return records, stats

    def read_live(
        self,
        packets: Iterable[PacketRecord],
        source_ref: str,
        read_stats: Optional[ReadStats] = None,
    ) -> tuple[list[PacketRecord], ReadStats]:
        """Normalize packets produced by a live capture session."""
        records: list[PacketRecord] = []
        stats = read_stats or ReadStats()
        for record in packets:
            normalized = normalize_record(record)
            normalized = apply_privacy(normalized, self.config.privacy)
            if len(records) < MAX_RETAINED_PACKETS:
                records.append(normalized)
        self._emit("progress", packets_read=len(records), source=source_ref)
        return records, stats

    # -- Stage 3: flows and statistics ---------------------------------------
    def analyze_flows(self, records: list[PacketRecord]) -> tuple[list[Flow], list[int]]:
        analyzer = FlowAnalyzer(idle_timeout=self.config.analysis.flow_idle_timeout)
        for record in records:
            analyzer.add_packet(record)
        result = analyzer.finish()
        self._emit("flows", flow_count=len(result.flows))
        return result.flows, result.unassigned_packet_ids

    def compute_statistics(self, records: list[PacketRecord], flows: list[Flow]):
        stats = compute_statistics(
            records,
            flows,
            host_volume_zscore=self.config.analysis.host_volume_zscore,
        )
        self._emit("statistics", total_packets=stats.total_packets, total_bytes=stats.total_bytes)
        return stats

    # -- Stage 4: rules ------------------------------------------------------
    def run_rules(self, records, flows, statistics) -> list[Alert]:
        context = build_rule_context(records, flows, statistics, self.config.analysis)
        alerts = self.rule_engine.evaluate(context)
        self._emit("rules", alert_count=len(alerts))
        return alerts

    # -- Stage 5: AI ---------------------------------------------------------
    def run_ai(self, statistics, flows, alerts, records, store, source, capture_format):
        service = self.ai_service or AIService(self.config.ai, self.config.privacy)
        self._emit("ai_start", provider=self.config.ai.provider, enabled=self.config.ai.enabled)
        result = service.analyze(
            statistics=statistics,
            flows=flows,
            alerts=alerts,
            records=records,
            store=store,
            source=source,
            capture_format=capture_format,
        )
        self._emit(
            "ai_done",
            succeeded=result.succeeded,
            provider=result.provider,
            duration_seconds=round(result.duration_seconds, 3),
        )
        return result

    # -- Orchestration -------------------------------------------------------
    def run_file(self, source: str) -> PipelineResult:
        """Run the full chain over a capture file."""
        started = time.monotonic()
        self._emit("start", source=source, source_type="file")

        records, read_stats = self.read_source(source, source_type="file")
        flows, unassigned = self.analyze_flows(records)
        statistics = self.compute_statistics(records, flows)
        alerts = self.run_rules(records, flows, statistics)

        store = EvidenceStore()
        store.add_packets(records)
        store.add_flows(flows)
        store.add_alerts(alerts)

        ai_result = self.run_ai(
            statistics, flows, alerts, records, store, source, read_stats.capture_format
        )

        return self._build_result(
            source=source,
            source_type="file",
            capture_format=read_stats.capture_format,
            records=records,
            flows=flows,
            alerts=alerts,
            statistics=statistics,
            read_stats=read_stats,
            ai_result=ai_result,
            store=store,
            unassigned_packets=unassigned,
            started=started,
        )

    def run_records(
        self,
        records: list[PacketRecord],
        source: str,
        source_type: str,
        read_stats: Optional[ReadStats] = None,
    ) -> PipelineResult:
        """Run the chain over already-captured records (live capture path)."""
        started = time.monotonic()
        flows, unassigned = self.analyze_flows(records)
        statistics = self.compute_statistics(records, flows)
        alerts = self.run_rules(records, flows, statistics)

        store = EvidenceStore()
        store.add_packets(records)
        store.add_flows(flows)
        store.add_alerts(alerts)

        stats = read_stats or ReadStats()
        ai_result = self.run_ai(
            statistics, flows, alerts, records, store, source, stats.capture_format
        )

        return self._build_result(
            source=source,
            source_type=source_type,
            capture_format=stats.capture_format,
            records=records,
            flows=flows,
            alerts=alerts,
            statistics=statistics,
            read_stats=stats,
            ai_result=ai_result,
            store=store,
            unassigned_packets=unassigned,
            started=started,
        )

    def _build_result(
        self,
        *,
        source: str,
        source_type: str,
        capture_format: Optional[str],
        records: list[PacketRecord],
        flows: list[Flow],
        alerts: list[Alert],
        statistics,
        read_stats: ReadStats,
        ai_result: AIAnalysisResult,
        store: EvidenceStore,
        unassigned_packets: list[int],
        started: float,
    ) -> PipelineResult:
        duration = time.monotonic() - started

        errors: list[str] = list(read_stats.read_errors)
        warnings: list[str] = []
        limitations = list(DEFAULT_LIMITATIONS)

        if read_stats.packets_failed:
            warnings.append(
                f"{read_stats.packets_failed} packet(s) could not be parsed completely."
            )
        if read_stats.truncated:
            warnings.append(
                f"Reading stopped at the configured max_packets limit "
                f"({self.config.capture.max_packets}); later packets were not analyzed."
            )
        if unassigned_packets:
            warnings.append(
                f"{len(unassigned_packets)} packet(s) had no IP/transport fields and were "
                "not assigned to a flow."
            )
        if store.packets_truncated:
            warnings.append(
                "Some packets were indexed but not retained in full; evidence detail for "
                "those packets is limited to identifiers."
            )
        if ai_result is not None and not ai_result.succeeded and ai_result.enabled:
            warnings.append(
                "AI analysis did not produce a validated finding. Deterministic results "
                "are unaffected."
            )
        if ai_result is not None and ai_result.enabled and not ai_result.finding.evidence_refs:
            warnings.append(
                "The AI finding contains no verified evidence references; treat its "
                "narrative as unverified."
            )

        statistics_dict = statistics.to_dict()
        statistics_dict["packet_totals"] = {
            "packets": statistics.total_packets,
            "bytes": statistics.total_bytes,
            "duration_seconds": round(statistics.duration_seconds, 3),
            "packets_per_second": statistics.packets_per_second,
            "bytes_per_second": statistics.bytes_per_second,
        }
        statistics_dict["dns"] = {
            "queries": statistics.dns_query_count,
            "responses": statistics.dns_response_count,
            "nxdomain": statistics.dns_nxdomain_count,
            "top_queries": statistics.dns_top_queries,
        }

        packet_details: list[dict] = []
        if self.config.report.include_packet_details:
            limit = self.config.report.max_packets_in_report
            packet_details = [record.to_dict() for record in records[:limit]]

        session = AnalysisSession(
            session_id=new_session_id(),
            started_at=utc_now_iso(),
            source=source,
            source_type=source_type,
            capture_format=capture_format,
            tool_version=TOOL_VERSION,
            packet_count=len(records),
            packets_failed=read_stats.packets_failed,
            statistics=statistics_dict,
            flows=[flow.to_dict() for flow in flows],
            alerts=[alert.to_dict() for alert in alerts],
            packets=packet_details,
            ai_analysis=ai_result.to_dict() if ai_result is not None else None,
            errors=errors,
            warnings=warnings,
            limitations=limitations,
            configuration=self.config.to_dict(include_secrets=True),
            environment=environment_info(),
            evidence_summary=store.summarize(),
            duration_seconds=round(duration, 4),
            packets_truncated=store.packets_truncated,
        )
        self._emit("complete", session_id=session.session_id)
        return PipelineResult(
            session=session,
            records=records,
            flows=flows,
            alerts=alerts,
            read_stats=read_stats,
            ai_result=ai_result,
        )
