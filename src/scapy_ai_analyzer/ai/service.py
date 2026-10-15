"""AI service: provider selection, request execution, and validation.

This is the only module the pipeline calls for AI work. It owns:

* provider construction from configuration,
* prompt building,
* the call with timeout and retry handling,
* response parsing and validation against the evidence store.

Failures are returned as a ``Finding`` with ``validation_status='rejected'``
rather than raised, because a missing AI provider must never invalidate the
deterministic analysis that already ran.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from ..config import AIConfig, PrivacyConfig
from ..evidence.evidence_store import EvidenceStore
from ..models.finding import Alert, Finding
from ..models.flow import Flow
from ..models.packet import PacketRecord
from ..analysis.statistics import TrafficStatistics
from .base import AIProvider, AIProviderError, AIRequest, AITimeoutError
from .prompt_builder import PromptBuilder
from .providers.mock_provider import MockProvider
from .schema import (
    CONFIDENCE_DISCLAIMER,
    build_rejected_finding,
    extract_json_payload,
    validate_response,
)

# Providers that are not the mock require explicit configuration.
REAL_PROVIDERS = {"openai_compatible"}


@dataclass
class AIAnalysisResult:
    """Result of one AI analysis attempt."""

    finding: Finding
    provider: str
    model: Optional[str] = None
    enabled: bool = True
    succeeded: bool = False
    duration_seconds: float = 0.0
    attempts: int = 0
    prompt_bytes: int = 0
    truncated: bool = False
    included_packet_refs: list[str] = field(default_factory=list)
    included_flow_refs: list[str] = field(default_factory=list)
    included_alert_refs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    token_usage: dict[str, Any] = field(default_factory=dict)
    # Transparency record: what was actually sent, without packet payloads.
    request_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = {
            "finding": self.finding.to_dict(),
            "provider": self.provider,
            "model": self.model,
            "enabled": self.enabled,
            "succeeded": self.succeeded,
            "duration_seconds": round(self.duration_seconds, 4),
            "attempts": self.attempts,
            "prompt_bytes": self.prompt_bytes,
            "prompt_truncated": self.truncated,
            "included_packet_refs": self.included_packet_refs,
            "included_flow_refs": self.included_flow_refs,
            "included_alert_refs": self.included_alert_refs,
            "errors": self.errors,
            "warnings": self.warnings,
            "token_usage": self.token_usage,
            "request_metadata": self.request_metadata,
            "confidence_disclaimer": CONFIDENCE_DISCLAIMER,
        }
        return data


def build_provider(config: AIConfig) -> AIProvider:
    """Instantiate the provider named in the configuration."""
    provider_name = (config.provider or "mock").strip().lower()

    if provider_name == "mock":
        return MockProvider(model=config.model)

    if provider_name in REAL_PROVIDERS:
        from .providers.openai_provider import OpenAICompatibleProvider

        return OpenAICompatibleProvider(
            model=config.model,
            api_key=config.api_key,
            base_url=config.base_url,
        )

    raise ValueError(
        f"Unknown AI provider '{config.provider}'. "
        f"Supported providers: mock, {', '.join(sorted(REAL_PROVIDERS))}."
    )


class AIService:
    """Runs AI analysis over analyzed session data."""

    def __init__(
        self,
        config: AIConfig,
        privacy: Optional[PrivacyConfig] = None,
        provider: Optional[AIProvider] = None,
    ) -> None:
        self.config = config
        self.privacy = privacy or PrivacyConfig()
        self.prompt_builder = PromptBuilder(config, self.privacy)
        self._provider = provider

    @property
    def provider(self) -> AIProvider:
        if self._provider is None:
            self._provider = build_provider(self.config)
        return self._provider

    def analyze(
        self,
        statistics: TrafficStatistics,
        flows: list[Flow],
        alerts: list[Alert],
        records: list[PacketRecord],
        store: EvidenceStore,
        source: str,
        capture_format: Optional[str] = None,
    ) -> AIAnalysisResult:
        """Build a prompt, call the provider, and validate the response.

        Never raises for provider or validation problems; those become a
        rejected finding so the report still contains everything else.
        """
        provider_name = (self.config.provider or "mock").strip().lower()

        if not self.config.enabled:
            return AIAnalysisResult(
                finding=build_rejected_finding(
                    "AI analysis was disabled by configuration.", provider_name, self.config.model
                ),
                provider=provider_name,
                model=self.config.model,
                enabled=False,
                succeeded=False,
                errors=["ai_disabled"],
            )

        prompt = self.prompt_builder.build(
            statistics=statistics,
            flows=flows,
            alerts=alerts,
            records=records,
            source=source,
            capture_format=capture_format,
        )
        request_metadata = {
            "system_prompt_bytes": len(prompt.system_prompt.encode("utf-8")),
            "user_prompt_bytes": len(prompt.user_prompt.encode("utf-8")),
            "included_packet_samples": len(prompt.included_packet_refs),
            "included_flows": len(prompt.included_flow_refs),
            "included_alerts": len(prompt.included_alert_refs),
            "raw_payloads_included": False,
            "privacy_redaction": {
                "redact_private_ips": self.privacy.redact_private_ips,
                "redact_mac_addresses": self.privacy.redact_mac_addresses,
            },
            "language": self.config.language,
        }

        try:
            provider = self.provider
        except Exception as exc:  # noqa: BLE001 - misconfiguration must not abort the run
            message = f"AI provider could not be initialized: {exc}"
            return AIAnalysisResult(
                finding=build_rejected_finding(message, provider_name, self.config.model),
                provider=provider_name,
                model=self.config.model,
                succeeded=False,
                prompt_bytes=prompt.approx_bytes,
                truncated=prompt.truncated,
                included_packet_refs=prompt.included_packet_refs,
                included_flow_refs=prompt.included_flow_refs,
                included_alert_refs=prompt.included_alert_refs,
                errors=[message],
                request_metadata=request_metadata,
            )

        if not provider.is_available():
            return AIAnalysisResult(
                finding=build_rejected_finding(
                    "AI provider is not configured (missing API key or model).",
                    provider.name,
                    provider.model,
                ),
                provider=provider.name,
                model=provider.model,
                succeeded=False,
                prompt_bytes=prompt.approx_bytes,
                truncated=prompt.truncated,
                included_packet_refs=prompt.included_packet_refs,
                included_flow_refs=prompt.included_flow_refs,
                included_alert_refs=prompt.included_alert_refs,
                errors=["provider_not_configured"],
                request_metadata=request_metadata,
            )

        request = AIRequest(
            system_prompt=prompt.system_prompt,
            user_prompt=prompt.user_prompt,
            timeout_seconds=self.config.timeout_seconds,
            max_retries=self.config.max_retries,
        )

        start = time.monotonic()
        try:
            response = provider.complete(request)
        except AIProviderError as exc:
            duration = time.monotonic() - start
            message = f"AI provider call failed: {exc}"
            if isinstance(exc, AITimeoutError):
                message = (
                    f"AI provider request timed out after "
                    f"{self.config.timeout_seconds:g}s: {exc}"
                )
            return AIAnalysisResult(
                finding=build_rejected_finding(message, provider.name, provider.model),
                provider=provider.name,
                model=provider.model,
                succeeded=False,
                duration_seconds=duration,
                prompt_bytes=prompt.approx_bytes,
                truncated=prompt.truncated,
                included_packet_refs=prompt.included_packet_refs,
                included_flow_refs=prompt.included_flow_refs,
                included_alert_refs=prompt.included_alert_refs,
                errors=[message],
                request_metadata=request_metadata,
            )
        except Exception as exc:  # noqa: BLE001 - unexpected provider bugs are contained here
            duration = time.monotonic() - start
            message = f"Unexpected AI provider error: {exc.__class__.__name__}: {exc}"
            return AIAnalysisResult(
                finding=build_rejected_finding(
                    message, provider.name, provider.model
                ),
                provider=provider.name,
                model=provider.model,
                succeeded=False,
                duration_seconds=duration,
                prompt_bytes=prompt.approx_bytes,
                truncated=prompt.truncated,
                errors=[message],
                request_metadata=request_metadata,
            )
        duration = time.monotonic() - start

        payload, parse_warnings = extract_json_payload(response.text)
        if payload is None:
            finding = build_rejected_finding(
                "AI response did not contain a valid JSON object.",
                response.provider,
                response.model,
            )
            finding.validation_warnings.extend(parse_warnings)
            return AIAnalysisResult(
                finding=finding,
                provider=response.provider,
                model=response.model,
                succeeded=False,
                duration_seconds=duration,
                attempts=response.attempts,
                prompt_bytes=prompt.approx_bytes,
                truncated=prompt.truncated,
                included_packet_refs=prompt.included_packet_refs,
                included_flow_refs=prompt.included_flow_refs,
                included_alert_refs=prompt.included_alert_refs,
                errors=["invalid_json_response"],
                warnings=parse_warnings,
                token_usage=_token_usage(response),
                request_metadata=request_metadata,
            )

        validation = validate_response(
            payload, store, provider=response.provider, model=response.model
        )
        if not validation.valid or validation.finding is None:
            detail = "; ".join(validation.errors)
            finding = build_rejected_finding(
                "AI response failed schema validation: " + detail,
                response.provider,
                response.model,
            )
            finding.validation_warnings.extend(validation.errors)
            return AIAnalysisResult(
                finding=finding,
                provider=response.provider,
                model=response.model,
                succeeded=False,
                duration_seconds=duration,
                attempts=response.attempts,
                prompt_bytes=prompt.approx_bytes,
                truncated=prompt.truncated,
                included_packet_refs=prompt.included_packet_refs,
                included_flow_refs=prompt.included_flow_refs,
                included_alert_refs=prompt.included_alert_refs,
                errors=[f"schema validation failed: {detail}"],
                warnings=validation.warnings,
                token_usage=_token_usage(response),
                request_metadata=request_metadata,
            )

        warnings = list(parse_warnings) + list(validation.warnings)
        if prompt.truncated:
            warnings.append("prompt_evidence_truncated")
            validation.finding.limitations.append(
                "The evidence sent to the AI was truncated to respect the size limit."
            )

        return AIAnalysisResult(
            finding=validation.finding,
            provider=response.provider,
            model=response.model,
            succeeded=True,
            duration_seconds=duration,
            attempts=response.attempts,
            prompt_bytes=prompt.approx_bytes,
            truncated=prompt.truncated,
            included_packet_refs=prompt.included_packet_refs,
            included_flow_refs=prompt.included_flow_refs,
            included_alert_refs=prompt.included_alert_refs,
            warnings=warnings,
            token_usage=_token_usage(response),
            request_metadata=request_metadata,
        )


def _token_usage(response: Any) -> dict[str, Any]:
    usage: dict[str, Any] = {}
    if getattr(response, "prompt_tokens", None) is not None:
        usage["prompt_tokens"] = response.prompt_tokens
    if getattr(response, "completion_tokens", None) is not None:
        usage["completion_tokens"] = response.completion_tokens
    return usage
