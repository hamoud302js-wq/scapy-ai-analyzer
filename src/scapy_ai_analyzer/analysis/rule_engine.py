"""Rule engine.

The rule engine runs *before* any AI call. It turns measurable patterns in the
capture into alerts. Every alert carries:

* the measured values that triggered it (``metrics``),
* the evidence references that support it,
* an explicit ``limitations`` list stating what the rule cannot conclude.

A rule fires on an observation, never on a verdict. "One source contacted 40
distinct destination ports in 12 seconds" is an observation. "This is a port
scan" is a conclusion that requires context the capture may not contain, and is
therefore left to the analyst (or the AI layer, which must also state its
uncertainty).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Optional, Sequence

from ..config import AnalysisConfig
from ..models.finding import SEVERITIES, Alert
from ..models.flow import Flow
from ..models.packet import PacketRecord
from .statistics import TrafficStatistics

# TCP flag bit for SYN, used to isolate connection attempts.
TCP_SYN = 0x02
TCP_ACK = 0x10
TCP_RST = 0x04

# Well-known ports excluded from scan fan-out when they dominate a capture.
COMMON_SERVICE_PORTS = {53, 67, 68, 80, 123, 443, 5353}


@dataclass
class RuleContext:
    """Everything a rule may inspect."""

    records: Sequence[PacketRecord]
    flows: Sequence[Flow]
    statistics: TrafficStatistics
    config: AnalysisConfig


@dataclass
class RuleDefinition:
    """Metadata describing a rule, exposed by ``rules list``."""

    rule_id: str
    name: str
    severity: str
    description: str
    limitations: list[str]


class Rule:
    """Base class for all rules."""

    definition: RuleDefinition

    def evaluate(self, context: RuleContext) -> list[Alert]:
        raise NotImplementedError


def _make_alert(
    rule: RuleDefinition,
    counter: int,
    description: str,
    reason: str,
    timestamp: float,
    *,
    window_start: Optional[float] = None,
    window_end: Optional[float] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    dst_ports: Optional[list[int]] = None,
    evidence_refs: Optional[list[str]] = None,
    packet_ids: Optional[list[int]] = None,
    flow_ids: Optional[list[str]] = None,
    metrics: Optional[dict[str, Any]] = None,
    extra_limitations: Optional[list[str]] = None,
) -> Alert:
    limitations = list(rule.limitations)
    if extra_limitations:
        limitations.extend(extra_limitations)
    return Alert(
        alert_id=f"alert-{counter:04d}",
        rule_id=rule.rule_id,
        rule_name=rule.name,
        severity=rule.severity,
        description=description,
        reason=reason,
        timestamp=timestamp,
        window_start=window_start,
        window_end=window_end,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_ports=sorted(dst_ports) if dst_ports else [],
        evidence_refs=list(evidence_refs or []),
        packet_ids=list(packet_ids or []),
        flow_ids=list(flow_ids or []),
        metrics=metrics or {},
        limitations=limitations,
    )


class PortScanRule(Rule):
    """One source contacting many distinct destination ports in a short window."""

    definition = RuleDefinition(
        rule_id="R001",
        name="Multiple destination ports contacted in a short window",
        severity="medium",
        description=(
            "A single source sent connection attempts to many distinct destination "
            "ports within a configurable time window."
        ),
        limitations=[
            "Distinct ports alone do not establish intent; load balancers, proxies, "
            "and monitoring tools produce the same pattern.",
            "If the capture began mid-session, earlier packets from this source are absent.",
            "UDP and TCP fan-out are evaluated separately and are not combined.",
        ],
    )

    def evaluate(self, context: RuleContext) -> list[Alert]:
        cfg = context.config
        alerts: list[Alert] = []
        counter = 0

        # Isolate connection attempts: TCP SYN without ACK, and standalone UDP.
        attempts: dict[str, list[tuple[float, int, int]]] = defaultdict(list)
        for record in context.records:
            if not record.src_ip or record.dst_port is None:
                continue
            if record.transport_protocol == "TCP":
                if record.tcp_flags_int is None:
                    continue
                if not (record.tcp_flags_int & TCP_SYN) or (record.tcp_flags_int & TCP_ACK):
                    continue
            elif record.transport_protocol == "UDP":
                # A UDP reply is not a connection attempt. Without a handshake to
                # rely on, exclude the two clear reply shapes: traffic from a
                # well-known service port, and application-level responses.
                if record.dst_port in COMMON_SERVICE_PORTS:
                    continue
                if record.src_port in COMMON_SERVICE_PORTS:
                    continue
                if record.dns_is_response:
                    continue
            else:
                continue
            attempts[record.src_ip].append(
                (record.timestamp, record.dst_port, record.packet_id)
            )

        for src_ip, events in attempts.items():
            events.sort()
            window: list[tuple[float, int, int]] = []
            for event in events:
                window.append(event)
                window_start = event[0] - cfg.scan_window_seconds
                window = [item for item in window if item[0] >= window_start]
                distinct_ports = {item[1] for item in window}
                if len(distinct_ports) >= cfg.scan_min_distinct_ports and len(window) >= cfg.scan_min_flows:
                    counter += 1
                    window_packet_ids = [item[2] for item in window]
                    alerts.append(
                        _make_alert(
                            self.definition,
                            counter,
                            description=(
                                f"Source {src_ip} contacted {len(distinct_ports)} distinct "
                                f"destination ports within {cfg.scan_window_seconds:.0f} seconds."
                            ),
                            reason=(
                                f"Observed {len(window)} connection attempts from {src_ip} "
                                f"across {len(distinct_ports)} distinct destination ports in a "
                                f"{cfg.scan_window_seconds:.0f}s window "
                                f"(threshold: {cfg.scan_min_distinct_ports} ports, "
                                f"{cfg.scan_min_flows} attempts)."
                            ),
                            timestamp=window[-1][0],
                            window_start=window[0][0],
                            window_end=window[-1][0],
                            src_ip=src_ip,
                            dst_ports=sorted(distinct_ports),
                            packet_ids=window_packet_ids,
                            evidence_refs=[f"packet-{pid}" for pid in window_packet_ids[:50]],
                            metrics={
                                "distinct_dst_ports": len(distinct_ports),
                                "attempts_in_window": len(window),
                                "window_seconds": cfg.scan_window_seconds,
                                "threshold_distinct_ports": cfg.scan_min_distinct_ports,
                            },
                        )
                    )
                    # Restart the window so a long scan yields separate, reviewable events.
                    window = []
        return alerts


class ConnectionFanoutRule(Rule):
    """One source opening connections to many distinct destinations."""

    definition = RuleDefinition(
        rule_id="R002",
        name="High connection fan-out to distinct destinations",
        severity="medium",
        description=(
            "A single source established or attempted connections to an unusually "
            "high number of distinct destination addresses."
        ),
        limitations=[
            "Content delivery networks and cloud services legitimately contact many "
            "addresses from one client.",
            "The rule counts destinations, not intent or success.",
        ],
    )

    def evaluate(self, context: RuleContext) -> list[Alert]:
        cfg = context.config
        per_source: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"destinations": set(), "packet_ids": [], "first": None, "last": None}
        )
        for record in context.records:
            if not record.src_ip or not record.dst_ip or record.transport_protocol != "TCP":
                continue
            if record.tcp_flags_int is None or not (record.tcp_flags_int & TCP_SYN):
                continue
            entry = per_source[record.src_ip]
            entry["destinations"].add(record.dst_ip)
            entry["packet_ids"].append(record.packet_id)
            if entry["first"] is None:
                entry["first"] = record.timestamp
            entry["last"] = record.timestamp

        alerts: list[Alert] = []
        counter = 0
        for src_ip, entry in per_source.items():
            count = len(entry["destinations"])
            if count >= cfg.fanout_min_distinct_destinations:
                counter += 1
                alerts.append(
                    _make_alert(
                        self.definition,
                        counter,
                        description=(
                            f"Source {src_ip} sent connection attempts to {count} distinct "
                            "destination addresses."
                        ),
                        reason=(
                            f"Observed SYN packets from {src_ip} targeting {count} distinct "
                            f"destination IPs (threshold: "
                            f"{cfg.fanout_min_distinct_destinations})."
                        ),
                        timestamp=entry["last"] or 0.0,
                        window_start=entry["first"],
                        window_end=entry["last"],
                        src_ip=src_ip,
                        packet_ids=entry["packet_ids"],
                        evidence_refs=[f"packet-{pid}" for pid in entry["packet_ids"][:50]],
                        metrics={
                            "distinct_destinations": count,
                            "syn_packets": len(entry["packet_ids"]),
                            "threshold_distinct_destinations": cfg.fanout_min_distinct_destinations,
                        },
                    )
                )
        return alerts


class DnsVolumeRule(Rule):
    """A source generating a high rate of DNS queries."""

    definition = RuleDefinition(
        rule_id="R003",
        name="High DNS query rate from a single source",
        severity="low",
        description=(
            "A source issued an elevated number of DNS queries within a short window."
        ),
        limitations=[
            "Caching resolvers, browsers, and OS services generate legitimate query bursts.",
            "Query volume alone does not indicate tunnelling or exfiltration.",
        ],
    )

    def evaluate(self, context: RuleContext) -> list[Alert]:
        cfg = context.config
        events: dict[str, list[tuple[float, int]]] = defaultdict(list)
        for record in context.records:
            if record.dns_query and not record.dns_is_response and record.src_ip:
                events[record.src_ip].append((record.timestamp, record.packet_id))

        alerts: list[Alert] = []
        counter = 0
        for src_ip, items in events.items():
            items.sort()
            window: list[tuple[float, int]] = []
            for item in items:
                window.append(item)
                cutoff = item[0] - cfg.dns_window_seconds
                window = [entry for entry in window if entry[0] >= cutoff]
                if len(window) >= cfg.dns_min_queries:
                    counter += 1
                    packet_ids = [entry[1] for entry in window]
                    alerts.append(
                        _make_alert(
                            self.definition,
                            counter,
                            description=(
                                f"Source {src_ip} issued {len(window)} DNS queries within "
                                f"{cfg.dns_window_seconds:.0f} seconds."
                            ),
                            reason=(
                                f"Query rate threshold reached: {len(window)} queries in "
                                f"{cfg.dns_window_seconds:.0f}s (threshold: "
                                f"{cfg.dns_min_queries})."
                            ),
                            timestamp=window[-1][0],
                            window_start=window[0][0],
                            window_end=window[-1][0],
                            src_ip=src_ip,
                            packet_ids=packet_ids,
                            evidence_refs=[f"packet-{pid}" for pid in packet_ids[:50]],
                            metrics={
                                "queries_in_window": len(window),
                                "window_seconds": cfg.dns_window_seconds,
                                "threshold_queries": cfg.dns_min_queries,
                            },
                        )
                    )
                    window = []
        return alerts


class DnsNxdomainRule(Rule):
    """A high share of DNS responses that report NXDOMAIN."""

    definition = RuleDefinition(
        rule_id="R004",
        name="Elevated NXDOMAIN response ratio",
        severity="low",
        description=(
            "A large share of observed DNS responses were NXDOMAIN, which can "
            "accompany domain-generation-algorithm behaviour or misconfiguration."
        ),
        limitations=[
            "Misconfigured clients, expired domains, and search-domain suffixes produce "
            "NXDOMAIN responses legitimately.",
            "The rule requires a minimum number of DNS responses before it evaluates.",
        ],
    )

    def evaluate(self, context: RuleContext) -> list[Alert]:
        responses = [r for r in context.records if r.dns_is_response]
        if len(responses) < 10:
            return []
        nxdomain = [r for r in responses if r.dns_rcode == "NXDOMAIN"]
        ratio = len(nxdomain) / len(responses)
        if ratio < context.config.dns_nxdomain_ratio:
            return []

        packet_ids = [r.packet_id for r in nxdomain]
        alert = _make_alert(
            self.definition,
            1,
            description=(
                f"{len(nxdomain)} of {len(responses)} DNS responses were NXDOMAIN "
                f"({ratio:.0%})."
            ),
            reason=(
                f"NXDOMAIN ratio {ratio:.2f} exceeds the configured threshold "
                f"{context.config.dns_nxdomain_ratio:.2f} across {len(responses)} responses."
            ),
            timestamp=responses[-1].timestamp,
            window_start=responses[0].timestamp,
            window_end=responses[-1].timestamp,
            packet_ids=packet_ids,
            evidence_refs=[f"packet-{pid}" for pid in packet_ids[:50]],
            metrics={
                "dns_responses": len(responses),
                "nxdomain_responses": len(nxdomain),
                "nxdomain_ratio": round(ratio, 4),
                "threshold_ratio": context.config.dns_nxdomain_ratio,
            },
        )
        return [alert]


class IncompleteHandshakeRule(Rule):
    """TCP flows where SYN was seen but the handshake never completed."""

    definition = RuleDefinition(
        rule_id="R005",
        name="Incomplete TCP handshakes",
        severity="low",
        description=(
            "TCP flows showed a SYN without a subsequent ACK, FIN, or RST within the capture."
        ),
        limitations=[
            "Packet loss, capture start/end boundaries, and filtered traffic all produce "
            "this pattern without any scanning.",
            "A capture that began after the handshake cannot show the missing packets.",
        ],
    )

    def evaluate(self, context: RuleContext) -> list[Alert]:
        syn_only = [f for f in context.flows if f.transport_protocol == "TCP" and f.is_syn_only]
        if len(syn_only) < 5:
            return []

        flow_ids = [f.flow_id for f in syn_only]
        packet_ids = [pid for f in syn_only for pid in f.packet_ids[:5]]
        return [
            _make_alert(
                self.definition,
                1,
                description=(
                    f"{len(syn_only)} TCP flows contain a SYN with no completion "
                    "(no ACK, FIN, or RST observed)."
                ),
                reason=(
                    f"Identified {len(syn_only)} TCP flows classified as SYN-only. "
                    "Reference flows: " + ", ".join(flow_ids[:10]) + "."
                ),
                timestamp=max(f.end_time for f in syn_only),
                window_start=min(f.start_time for f in syn_only),
                window_end=max(f.end_time for f in syn_only),
                flow_ids=flow_ids,
                packet_ids=packet_ids,
                evidence_refs=flow_ids + [f"packet-{pid}" for pid in packet_ids[:20]],
                metrics={
                    "syn_only_flow_count": len(syn_only),
                    "threshold": 5,
                },
            )
        ]


class MalformedPacketRule(Rule):
    """Packets that could not be fully parsed."""

    definition = RuleDefinition(
        rule_id="R006",
        name="Malformed or unparsable packets",
        severity="info",
        description=(
            "One or more packets could not be parsed into a complete protocol record."
        ),
        limitations=[
            "Truncated captures and unsupported protocols commonly produce this result.",
            "A parse failure is a data-quality observation, not a security indicator.",
        ],
    )

    def evaluate(self, context: RuleContext) -> list[Alert]:
        failed = [r for r in context.records if r.parse_status in ("failed", "partial")]
        if not failed:
            return []
        packet_ids = [r.packet_id for r in failed]
        return [
            _make_alert(
                self.definition,
                1,
                description=f"{len(failed)} packets had parse warnings or failures.",
                reason=(
                    f"Parse status counts: "
                    + ", ".join(
                        f"{status}={count}"
                        for status, count in context.statistics.parse_status_counts.items()
                    )
                ),
                timestamp=failed[-1].timestamp,
                packet_ids=packet_ids,
                evidence_refs=[f"packet-{pid}" for pid in packet_ids[:50]],
                metrics={
                    "packets_with_warnings": len(failed),
                    "parse_status_counts": dict(context.statistics.parse_status_counts),
                },
            )
        ]


class HostVolumeAnomalyRule(Rule):
    """Hosts whose byte volume is a statistical outlier in this capture."""

    definition = RuleDefinition(
        rule_id="R007",
        name="Host traffic volume outlier",
        severity="info",
        description="One or more hosts transferred a statistically unusual byte volume.",
        limitations=[
            "The test is computed within a single capture; it is not a baseline comparison "
            "against normal network behaviour.",
            "The result is a descriptive statistic, not evidence of compromise.",
        ],
    )

    def evaluate(self, context: RuleContext) -> list[Alert]:
        anomalies = context.statistics.volume_anomaly_hosts
        if not anomalies:
            return []
        alerts: list[Alert] = []
        for index, anomaly in enumerate(anomalies, start=1):
            alerts.append(
                _make_alert(
                    self.definition,
                    index,
                    description=(
                        f"Host {anomaly['ip']} transferred {anomaly['bytes']} bytes, "
                        f"a z-score of {anomaly['zscore']} against the capture mean."
                    ),
                    reason=(
                        f"Bytes={anomaly['bytes']} vs capture mean {anomaly['mean_bytes']} "
                        f"(z-score {anomaly['zscore']}, threshold "
                        f"{context.config.host_volume_zscore})."
                    ),
                    timestamp=context.statistics.last_timestamp or 0.0,
                    src_ip=anomaly["ip"],
                    evidence_refs=[anomaly["ip"]],
                    metrics=anomaly,
                )
            )
        return alerts


class TcpResetRule(Rule):
    """A high number of TCP RST packets from a single source."""

    definition = RuleDefinition(
        rule_id="R008",
        name="Elevated TCP reset rate from one source",
        severity="low",
        description="A source emitted a high number of TCP RST packets.",
        limitations=[
            "Closed ports, stale connections, and middlebox resets all produce RSTs.",
            "A reset rate is not by itself proof of scanning or attack traffic.",
        ],
    )

    def evaluate(self, context: RuleContext) -> list[Alert]:
        per_source: dict[str, list[int]] = defaultdict(list)
        timestamps: dict[str, list[float]] = defaultdict(list)
        for record in context.records:
            if record.tcp_flags_int is None or not record.src_ip:
                continue
            if record.tcp_flags_int & TCP_RST:
                per_source[record.src_ip].append(record.packet_id)
                timestamps[record.src_ip].append(record.timestamp)

        alerts: list[Alert] = []
        counter = 0
        threshold = max(20, context.config.scan_min_flows)
        for src_ip, packet_ids in per_source.items():
            if len(packet_ids) >= threshold:
                counter += 1
                alerts.append(
                    _make_alert(
                        self.definition,
                        counter,
                        description=(
                            f"Source {src_ip} sent {len(packet_ids)} TCP RST packets."
                        ),
                        reason=(
                            f"RST count {len(packet_ids)} reached the threshold {threshold}."
                        ),
                        timestamp=max(timestamps[src_ip]),
                        window_start=min(timestamps[src_ip]),
                        window_end=max(timestamps[src_ip]),
                        src_ip=src_ip,
                        packet_ids=packet_ids,
                        evidence_refs=[f"packet-{pid}" for pid in packet_ids[:50]],
                        metrics={"rst_count": len(packet_ids), "threshold": threshold},
                    )
                )
        return alerts


class IcmpDiagnosticRule(Rule):
    """A burst of ICMP diagnostic messages, which can indicate host discovery."""

    definition = RuleDefinition(
        rule_id="R009",
        name="ICMP diagnostic message burst",
        severity="low",
        description="ICMP echo or unreachable messages were observed at an elevated rate.",
        limitations=[
            "Network monitoring, path MTU discovery, and outage conditions produce ICMP bursts.",
            "Presence of ICMP traffic is normal on most networks.",
        ],
    )

    def evaluate(self, context: RuleContext) -> list[Alert]:
        per_source: dict[str, list[int]] = defaultdict(list)
        timestamps: dict[str, list[float]] = defaultdict(list)
        for record in context.records:
            if record.transport_protocol == "ICMP" and record.src_ip:
                per_source[record.src_ip].append(record.packet_id)
                timestamps[record.src_ip].append(record.timestamp)

        alerts: list[Alert] = []
        counter = 0
        threshold = max(50, context.config.scan_min_flows * 3)
        for src_ip, packet_ids in per_source.items():
            if len(packet_ids) >= threshold:
                counter += 1
                alerts.append(
                    _make_alert(
                        self.definition,
                        counter,
                        description=(
                            f"Source {src_ip} sent {len(packet_ids)} ICMP messages."
                        ),
                        reason=f"ICMP count {len(packet_ids)} reached the threshold {threshold}.",
                        timestamp=max(timestamps[src_ip]),
                        window_start=min(timestamps[src_ip]),
                        window_end=max(timestamps[src_ip]),
                        src_ip=src_ip,
                        packet_ids=packet_ids,
                        evidence_refs=[f"packet-{pid}" for pid in packet_ids[:50]],
                        metrics={"icmp_count": len(packet_ids), "threshold": threshold},
                    )
                )
        return alerts


ALL_RULES: list[Rule] = [
    PortScanRule(),
    ConnectionFanoutRule(),
    DnsVolumeRule(),
    DnsNxdomainRule(),
    IncompleteHandshakeRule(),
    MalformedPacketRule(),
    HostVolumeAnomalyRule(),
    TcpResetRule(),
    IcmpDiagnosticRule(),
]


class RuleEngine:
    """Runs the configured rule set and collects alerts."""

    def __init__(self, rules: Optional[Iterable[Rule]] = None) -> None:
        self.rules = list(rules) if rules is not None else list(ALL_RULES)

    def list_rules(self) -> list[RuleDefinition]:
        return [rule.definition for rule in self.rules]

    def evaluate(self, context: RuleContext) -> list[Alert]:
        """Run every rule, keeping alerts ordered by time and renumbering ids."""
        alerts: list[Alert] = []
        for rule in self.rules:
            try:
                alerts.extend(rule.evaluate(context))
            except Exception as exc:  # noqa: BLE001 - one bad rule must not stop analysis
                alerts.append(
                    Alert(
                        alert_id="alert-0000",
                        rule_id=rule.definition.rule_id,
                        rule_name=rule.definition.name,
                        severity="info",
                        description=f"Rule {rule.definition.rule_id} failed to evaluate.",
                        reason=f"{exc.__class__.__name__}: {exc}",
                        timestamp=0.0,
                        limitations=["This rule produced no result; treat its findings as absent."],
                    )
                )

        alerts.sort(key=lambda a: (a.timestamp, a.rule_id))
        for index, alert in enumerate(alerts, start=1):
            alert.alert_id = f"alert-{index:04d}"
        return alerts


def build_rule_context(
    records: Sequence[PacketRecord],
    flows: Sequence[Flow],
    statistics: TrafficStatistics,
    config: AnalysisConfig,
) -> RuleContext:
    return RuleContext(records=records, flows=flows, statistics=statistics, config=config)
