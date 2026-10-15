"""Provider interface for the AI layer.

Every provider implements the same small contract so the rest of the system
never depends on a specific vendor. A provider receives a prepared prompt and
returns the raw text response; parsing and validation happen outside it, in
:mod:`scapy_ai_analyzer.ai.schema`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


class AIProviderError(Exception):
    """Base class for provider failures."""


class AITimeoutError(AIProviderError):
    """The provider did not answer within the configured timeout."""


class AIResponseError(AIProviderError):
    """The provider answered with an unusable or error response."""


@dataclass
class AIRequest:
    """A prompt prepared for a provider."""

    system_prompt: str
    user_prompt: str
    timeout_seconds: float = 30.0
    max_retries: int = 2
    metadata: dict = field(default_factory=dict)


@dataclass
class AIResponse:
    """A provider response."""

    text: str
    provider: str
    model: Optional[str] = None
    attempts: int = 1
    # Token accounting when the provider reports it.
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None


class AIProvider:
    """Base class for AI providers."""

    name = "base"

    def __init__(self, model: Optional[str] = None, **options) -> None:
        self.model = model
        self.options = options

    def is_available(self) -> bool:
        """Report whether the provider is configured well enough to attempt a call."""
        return True

    def complete(self, request: AIRequest) -> AIResponse:
        raise NotImplementedError

    def describe(self) -> dict:
        """Return non-secret provider metadata for the report."""
        return {
            "provider": self.name,
            "model": self.model,
            "available": self.is_available(),
        }
