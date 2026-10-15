"""Evidence store.

Every claim in a report must be traceable to something observed. The store
holds the packets, flows, and alerts that exist in a session and exposes a
lookup so that references produced by the rule engine or the AI layer can be
verified.

``verify_references`` is the enforcement point: any reference that does not
resolve to a stored object is reported as invalid instead of being silently
accepted into a report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from ..models.finding import Alert
from ..models.flow import Flow
from ..models.packet import PacketRecord


@dataclass
class ReferenceCheck:
    """Outcome of validating a list of evidence references."""

    valid: list[str] = field(default_factory=list)
    invalid: list[str] = field(default_factory=list)

    @property
    def all_valid(self) -> bool:
        return not self.invalid


class EvidenceStore:
    """In-memory index of session evidence.

    Packets are stored in full up to ``max_packets``; beyond that only the
    index is kept so a very large capture cannot exhaust memory. Flows and
    alerts are always stored because they are already aggregates.
    """

    def __init__(self, max_packets: int = 200_000) -> None:
        self.max_packets = max_packets
        self._packets: dict[int, PacketRecord] = {}
        self._packet_ids: set[int] = set()
        self._flows: dict[str, Flow] = {}
        self._alerts: dict[str, Alert] = {}
        self._packets_truncated = False

    def add_packet(self, record: PacketRecord) -> None:
        self._packet_ids.add(record.packet_id)
        if len(self._packets) < self.max_packets:
            self._packets[record.packet_id] = record
        else:
            self._packets_truncated = True

    def add_packets(self, records: Iterable[PacketRecord]) -> None:
        for record in records:
            self.add_packet(record)

    def add_flow(self, flow: Flow) -> None:
        self._flows[flow.flow_id] = flow

    def add_flows(self, flows: Iterable[Flow]) -> None:
        for flow in flows:
            self.add_flow(flow)

    def add_alert(self, alert: Alert) -> None:
        self._alerts[alert.alert_id] = alert

    def add_alerts(self, alerts: Iterable[Alert]) -> None:
        for alert in alerts:
            self.add_alert(alert)

    def get_packet(self, packet_id: int) -> Optional[PacketRecord]:
        return self._packets.get(packet_id)

    def get_flow(self, flow_id: str) -> Optional[Flow]:
        return self._flows.get(flow_id)

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        return self._alerts.get(alert_id)

    @property
    def packet_count(self) -> int:
        return len(self._packet_ids)

    @property
    def stored_packet_count(self) -> int:
        return len(self._packets)

    @property
    def packets_truncated(self) -> bool:
        return self._packets_truncated

    @property
    def flows(self) -> list[Flow]:
        return list(self._flows.values())

    @property
    def alerts(self) -> list[Alert]:
        return list(self._alerts.values())

    def reference_exists(self, reference: str) -> bool:
        """Check whether a reference string resolves to stored evidence."""
        if not isinstance(reference, str):
            return False
        ref = reference.strip()
        if ref.startswith("packet-"):
            suffix = ref.removeprefix("packet-")
            return suffix.isdigit() and int(suffix) in self._packet_ids
        if ref.startswith("flow-"):
            return ref in self._flows
        if ref.startswith("alert-"):
            return ref in self._alerts
        # Bare integers are accepted as packet references for convenience.
        if ref.isdigit():
            return int(ref) in self._packet_ids
        return False

    def verify_references(self, references: Iterable[str]) -> ReferenceCheck:
        """Split references into valid and invalid sets, preserving order."""
        check = ReferenceCheck()
        seen: set[str] = set()
        for reference in references:
            if not isinstance(reference, str):
                continue
            ref = reference.strip()
            if not ref or ref in seen:
                continue
            seen.add(ref)
            if self.reference_exists(ref):
                check.valid.append(ref)
            else:
                check.invalid.append(ref)
        return check

    def packet_reference(self, packet_id: int) -> str:
        return f"packet-{packet_id}"

    def flow_reference(self, flow_id: str) -> str:
        return flow_id

    def alert_reference(self, alert_id: str) -> str:
        return alert_id

    def summarize(self) -> dict[str, Any]:
        return {
            "packets_indexed": self.packet_count,
            "packets_stored_in_full": self.stored_packet_count,
            "packets_truncated": self._packets_truncated,
            "flows": len(self._flows),
            "alerts": len(self._alerts),
        }
