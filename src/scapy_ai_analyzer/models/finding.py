"""Finding and alert models.

An ``Alert`` is produced by the deterministic rule engine. A ``Finding`` is
produced by the AI layer and must reference evidence that actually exists.

Design rule enforced throughout: an observed anomaly ("many connections to
distinct ports") is not a security verdict ("this is a confirmed port scan").
The models keep ``observations`` and ``limitations`` as separate fields so the
distinction survives all the way into the report.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional

SEVERITIES = ("info", "low", "medium", "high", "critical")

# Human-readable rule for every severity value.
SEVERITY_DESCRIPTIONS = {
    "info": "Informational observation, no action implied.",
    "low": "Minor anomaly worth noting; benign explanations are likely.",
    "medium": "Anomaly that warrants review; not a confirmed incident.",
    "high": "Strong indicator requiring investigation; still not a verdict.",
    "critical": "Indicator with severe potential impact; requires immediate human review.",
}


@dataclass
class Alert:
    """A rule-engine alert.

    ``reason`` explains why the rule fired in terms of measured values, and
    ``limitations`` records what the rule cannot conclude.
    """

    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    description: str
    reason: str
    timestamp: float
    window_start: Optional[float] = None
    window_end: Optional[float] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_ports: list[int] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    packet_ids: list[int] = field(default_factory=list)
    flow_ids: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Alert":
        payload = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**payload)


@dataclass
class Finding:
    """A validated AI finding, tied to real evidence references."""

    analysis_summary: str
    finding_type: str
    severity: str
    confidence: Optional[float]
    observations: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    alternative_explanations: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    recommended_next_steps: list[str] = field(default_factory=list)
    provider: Optional[str] = None
    model: Optional[str] = None
    # Set when the AI response was rejected or degraded; the report shows this.
    validation_status: str = "valid"
    validation_warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        payload = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**payload)
