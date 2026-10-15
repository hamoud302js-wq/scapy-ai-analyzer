"""OpenAI-compatible chat completions provider.

Uses only the standard library so the project has no hard third-party HTTP
dependency. Works with any endpoint that implements the OpenAI chat completions
request/response shape.

The API key is read from configuration (which itself reads it from the
environment) and is sent only in the Authorization header. It is never logged,
never written to a report, and never included in an error message.
"""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from ..base import (
    AIProvider,
    AIProviderError,
    AIRequest,
    AIResponse,
    AITimeoutError,
)

# Status codes worth retrying: rate limits and transient server errors.
RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}


class OpenAICompatibleProvider(AIProvider):
    """Minimal chat completions client."""

    name = "openai_compatible"

    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        max_tokens: int = 1500,
        temperature: float = 0.0,
        **options: Any,
    ) -> None:
        super().__init__(model=model, **options)
        self.api_key = api_key
        self.base_url = (base_url or "https://api.openai.com/v1").rstrip("/")
        self.max_tokens = max_tokens
        self.temperature = temperature

    def is_available(self) -> bool:
        return bool(self.api_key) and bool(self.model)

    def describe(self) -> dict:
        return {
            "provider": self.name,
            "model": self.model,
            "base_url": self.base_url,
            "available": self.is_available(),
            "api_key_configured": bool(self.api_key),
        }

    def complete(self, request: AIRequest) -> AIResponse:
        if not self.is_available():
            raise AIProviderError(
                "Provider is not configured. Set the API key and model, or use the mock provider."
            )

        body = json.dumps(
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": request.system_prompt},
                    {"role": "user", "content": request.user_prompt},
                ],
                "temperature": self.temperature,
                "max_tokens": self.max_tokens,
                "response_format": {"type": "json_object"},
            }
        ).encode("utf-8")

        attempts_allowed = max(1, request.max_retries + 1)
        last_error: Optional[Exception] = None

        for attempt in range(1, attempts_allowed + 1):
            try:
                return self._send(body, request, attempt)
            except AITimeoutError as exc:
                last_error = exc
            except AIProviderError as exc:
                last_error = exc
                message = str(exc)
                # Only retry on transient conditions.
                if not any(
                    token in message for token in ("rate limit", "HTTP 5", "HTTP 429", "timed out")
                ):
                    raise
            if attempt < attempts_allowed:
                time.sleep(min(2 ** (attempt - 1), 8))

        raise AIProviderError(f"Provider failed after {attempts_allowed} attempt(s): {last_error}")

    def _send(self, body: bytes, request: AIRequest, attempt: int) -> AIResponse:
        url = f"{self.base_url}/chat/completions"
        http_request = urllib.request.Request(url, data=body, method="POST")
        http_request.add_header("Content-Type", "application/json")
        http_request.add_header("Authorization", f"Bearer {self.api_key}")
        http_request.add_header("Accept", "application/json")

        try:
            with urllib.request.urlopen(http_request, timeout=request.timeout_seconds) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except socket.timeout as exc:
            raise AITimeoutError("Request timed out.") from exc
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                error_body = json.loads(exc.read().decode("utf-8", errors="replace"))
                # Provider error messages can echo the request; keep it short and
                # never include headers or the API key.
                detail = str(error_body.get("error", {}).get("message", ""))[:200]
            except Exception:  # noqa: BLE001
                detail = ""
            if exc.code == 429:
                raise AIProviderError(f"Rate limit exceeded (HTTP 429). {detail}".strip()) from exc
            raise AIProviderError(f"HTTP {exc.code} from provider. {detail}".strip()) from exc
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            if isinstance(reason, socket.timeout):
                raise AITimeoutError("Request timed out.") from exc
            raise AIProviderError(f"Connection error: {reason}") from exc
        except TimeoutError as exc:
            raise AITimeoutError("Request timed out.") from exc

        return self._parse_response(raw, attempt)

    def _parse_response(self, raw: str, attempt: int) -> AIResponse:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AIProviderError("Provider returned a non-JSON response envelope.") from exc

        if isinstance(payload, dict) and "error" in payload:
            message = str(payload["error"])[:200]
            raise AIProviderError(f"Provider returned an error: {message}")

        try:
            choice = payload["choices"][0]
            content = choice["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AIProviderError("Provider response is missing choices[0].message.content.") from exc

        usage = payload.get("usage") or {}
        return AIResponse(
            text=content or "",
            provider=self.name,
            model=payload.get("model", self.model),
            attempts=attempt,
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
        )
