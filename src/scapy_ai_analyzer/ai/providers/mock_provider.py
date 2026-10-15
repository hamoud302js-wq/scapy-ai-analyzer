"""Deterministic mock provider.

This provider exists so the whole pipeline -- including validation, evidence
checking, and reporting -- can be exercised in tests and in offline runs without
network access or an API key.

It is *not* an AI. It parses the prompt it is given and echoes back a structured
finding built strictly from the alerts present in that prompt. That makes it a
faithful stand-in for the contract (JSON shape, evidence references) without
pretending to reason.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

from ..base import AIProvider, AIRequest, AIResponse

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


class MockProvider(AIProvider):
    """Returns a schema-valid finding derived from the prompt's own alerts."""

    name = "mock"

    def __init__(
        self,
        model: Optional[str] = None,
        response_override: Optional[str] = None,
        fail_mode: Optional[str] = None,
        **options: Any,
    ) -> None:
        super().__init__(model=model or "mock-deterministic-v1", **options)
        # Test hooks: force a specific raw response or a specific failure.
        self.response_override = response_override
        self.fail_mode = fail_mode

    def is_available(self) -> bool:
        return True

    def complete(self, request: AIRequest) -> AIResponse:
        if self.fail_mode == "timeout":
            from ..base import AITimeoutError

            raise AITimeoutError("Mock provider simulated a timeout.")
        if self.fail_mode == "error":
            from ..base import AIResponseError

            raise AIResponseError("Mock provider simulated a provider error.")
        if self.fail_mode == "malformed":
            return AIResponse(
                text="This is not JSON at all.",
                provider=self.name,
                model=self.model,
                attempts=1,
            )
        if self.fail_mode == "wrong_schema":
            return AIResponse(
                text=json.dumps({"analysis_summary": "Missing required fields."}),
                provider=self.name,
                model=self.model,
                attempts=1,
            )
        if self.fail_mode == "bad_refs":
            return AIResponse(
                text=json.dumps(
                    {
                        "analysis_summary": "Referenced evidence that does not exist.",
                        "finding_type": "possible_port_scan",
                        "severity": "high",
                        "confidence": 0.99,
                        "observations": ["Invented observation"],
                        "evidence_refs": ["packet-999999", "flow-9999", "alert-9999"],
                        "alternative_explanations": [],
                        "limitations": [],
                        "recommended_next_steps": [],
                    }
                ),
                provider=self.name,
                model=self.model,
                attempts=1,
            )
        if self.response_override is not None:
            return AIResponse(
                text=self.response_override,
                provider=self.name,
                model=self.model,
                attempts=1,
            )

        return AIResponse(
            text=json.dumps(self._build_payload(request.user_prompt)),
            provider=self.name,
            model=self.model,
            attempts=1,
        )

    def _extract_payload(self, user_prompt: str) -> Optional[dict]:
        match = re.search(r"\{.*\}", user_prompt, re.DOTALL)
        if not match:
            return None
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None

    def _build_payload(self, user_prompt: str) -> dict:
        payload = self._extract_payload(user_prompt) or {}
        alerts = payload.get("alerts", []) or []
        session = payload.get("session", {}) or {}
        flows = payload.get("flows", []) or []

        if not alerts:
            return {
                "analysis_summary": (
                    "No rule-based indicators were raised for this capture. "
                    "Traffic appears consistent with ordinary activity, though the "
                    "capture may not be representative."
                ),
                "finding_type": "no_indicators",
                "severity": "info",
                "confidence": 0.5,
                "observations": [
                    f"Packets analyzed: {session.get('packet_totals', {}).get('packets', 0)}",
                    f"Flows observed: {session.get('flow_summary', {}).get('flow_count', 0)}",
                ],
                "evidence_refs": [f["ref"] for f in flows[:3]],
                "alternative_explanations": [
                    "The capture window may be too short to show the activity of interest.",
                ],
                "limitations": [
                    "Absence of alerts does not mean absence of malicious activity.",
                    "Detection depends on the configured rule thresholds.",
                ],
                "recommended_next_steps": [
                    "Confirm the capture window covers the period of interest.",
                ],
            }

        top_alert = max(alerts, key=lambda a: SEVERITY_ORDER.index(a.get("severity", "info")))
        refs: list[str] = []
        for alert in alerts[:5]:
            if alert.get("ref"):
                refs.append(alert["ref"])
            refs.extend(alert.get("evidence_refs", [])[:3])
        for flow in flows[:2]:
            if flow.get("ref"):
                refs.append(flow["ref"])
        # Keep order, drop duplicates.
        refs = list(dict.fromkeys(refs))

        observations: list[str] = []
        for alert in alerts[:5]:
            observations.append(
                f"{alert.get('rule_id')}: {alert.get('description', '').strip()}"
            )

        alternatives = [
            "Legitimate administrative or monitoring tooling may produce the same pattern.",
            "Incomplete capture data can make a partial sequence look anomalous.",
        ]
        limitations: list[str] = []
        for alert in alerts[:5]:
            limitations.extend(alert.get("limitations", [])[:1])
        limitations.append(
            "This finding is derived from rule alerts; it is not a confirmed security incident."
        )

        return {
            "analysis_summary": (
                f"{len(alerts)} rule-based indicator(s) were raised. The most severe is "
                f"{top_alert.get('rule_name', 'an unnamed rule')} "
                f"({top_alert.get('severity', 'info')}): "
                f"{top_alert.get('description', '').strip()}"
            ),
            "finding_type": "rule_indicator_review",
            "severity": top_alert.get("severity", "info"),
            "confidence": 0.6,
            "observations": observations,
            "evidence_refs": refs,
            "alternative_explanations": alternatives,
            "limitations": limitations,
            "recommended_next_steps": [
                "Review the referenced alerts and their supporting packets.",
                "Compare the observed pattern against the expected baseline for this network.",
            ],
        }
