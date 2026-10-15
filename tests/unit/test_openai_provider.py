"""Tests for the OpenAI-compatible provider.

These run against a local stub HTTP server, so they exercise the real request
path -- URL building, headers, retry logic, error mapping, and response parsing
-- without contacting any external service and without an API key.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from scapy_ai_analyzer.ai.base import AIProviderError, AIRequest, AITimeoutError
from scapy_ai_analyzer.ai.providers.openai_provider import OpenAICompatibleProvider


class _StubHandler(BaseHTTPRequestHandler):
    """Records requests and returns a scripted response."""

    def log_message(self, *args):  # silence test output
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        self.server.requests.append(
            {
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "body": json.loads(raw),
            }
        )
        script = self.server.script.pop(0) if self.server.script else {"status": 200, "body": {}}
        self.send_response(script.get("status", 200))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        payload = script.get("body", {})
        if isinstance(payload, str):
            self.wfile.write(payload.encode("utf-8"))
        else:
            self.wfile.write(json.dumps(payload).encode("utf-8"))


@pytest.fixture()
def stub_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubHandler)
    server.requests = []
    server.script = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def _base_url(server) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}/v1"


def _request(**kwargs) -> AIRequest:
    defaults = dict(
        system_prompt="system",
        user_prompt="user",
        timeout_seconds=5,
        max_retries=0,
    )
    defaults.update(kwargs)
    return AIRequest(**defaults)


def _ok_body(content: str = '{"analysis_summary": "ok"}') -> dict:
    return {
        "model": "stub-model",
        "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 7},
    }


class TestConfiguration:
    def test_import_path_is_correct(self):
        """Regression: the provider must import its base classes from ai.base."""
        provider = OpenAICompatibleProvider(model="m", api_key="k")
        assert provider.name == "openai_compatible"

    def test_not_available_without_key(self):
        assert not OpenAICompatibleProvider(model="m", api_key=None).is_available()

    def test_not_available_without_model(self):
        assert not OpenAICompatibleProvider(model=None, api_key="k").is_available()

    def test_available_with_key_and_model(self):
        assert OpenAICompatibleProvider(model="m", api_key="k").is_available()

    def test_complete_without_configuration_raises(self):
        provider = OpenAICompatibleProvider(model=None, api_key=None)
        with pytest.raises(AIProviderError, match="not configured"):
            provider.complete(_request())

    def test_describe_never_exposes_the_key(self):
        provider = OpenAICompatibleProvider(model="m", api_key="super-secret", base_url="http://x")
        described = json.dumps(provider.describe())
        assert "super-secret" not in described
        assert provider.describe()["api_key_configured"] is True


class TestProviderFactory:
    def test_build_provider_constructs_the_real_provider(self):
        """Regression: build_provider must import the real provider successfully."""
        from scapy_ai_analyzer.ai.service import build_provider
        from scapy_ai_analyzer.config import AIConfig

        config = AIConfig(provider="openai_compatible", model="m", api_key="k")
        provider = build_provider(config)
        assert isinstance(provider, OpenAICompatibleProvider)
        assert provider.is_available()

    def test_build_provider_rejects_unknown_names(self):
        from scapy_ai_analyzer.ai.service import build_provider
        from scapy_ai_analyzer.config import AIConfig

        with pytest.raises(ValueError, match="Unknown AI provider"):
            build_provider(AIConfig(provider="does-not-exist"))

    def test_build_provider_returns_mock_by_default(self):
        from scapy_ai_analyzer.ai.providers.mock_provider import MockProvider
        from scapy_ai_analyzer.ai.service import build_provider
        from scapy_ai_analyzer.config import AIConfig

        assert isinstance(build_provider(AIConfig(provider="mock")), MockProvider)


class TestRequestShape:
    def test_successful_response_is_parsed(self, stub_server):
        stub_server.script = [{"status": 200, "body": _ok_body()}]
        provider = OpenAICompatibleProvider(
            model="stub-model", api_key="k", base_url=_base_url(stub_server)
        )
        response = provider.complete(_request())
        assert response.text == '{"analysis_summary": "ok"}'
        assert response.provider == "openai_compatible"
        assert response.model == "stub-model"
        assert response.prompt_tokens == 11
        assert response.completion_tokens == 7

    def test_posts_to_chat_completions(self, stub_server):
        stub_server.script = [{"status": 200, "body": _ok_body()}]
        provider = OpenAICompatibleProvider(
            model="stub-model", api_key="k", base_url=_base_url(stub_server)
        )
        provider.complete(_request())
        assert stub_server.requests[0]["path"] == "/v1/chat/completions"

    def test_sends_both_prompts(self, stub_server):
        stub_server.script = [{"status": 200, "body": _ok_body()}]
        provider = OpenAICompatibleProvider(
            model="stub-model", api_key="k", base_url=_base_url(stub_server)
        )
        provider.complete(_request(system_prompt="SYS", user_prompt="USR"))
        body = stub_server.requests[0]["body"]
        messages = {m["role"]: m["content"] for m in body["messages"]}
        assert messages["system"] == "SYS"
        assert messages["user"] == "USR"
        assert body["model"] == "stub-model"
        assert body["response_format"] == {"type": "json_object"}

    def test_sends_key_as_bearer_token(self, stub_server):
        stub_server.script = [{"status": 200, "body": _ok_body()}]
        provider = OpenAICompatibleProvider(
            model="stub-model", api_key="k", base_url=_base_url(stub_server)
        )
        provider.complete(_request())
        assert stub_server.requests[0]["authorization"] == "Bearer k"


class TestErrorMapping:
    def test_non_json_envelope_is_rejected(self, stub_server):
        stub_server.script = [{"status": 200, "body": "not json at all"}]
        provider = OpenAICompatibleProvider(
            model="m", api_key="k", base_url=_base_url(stub_server)
        )
        with pytest.raises(AIProviderError, match="non-JSON"):
            provider.complete(_request())

    def test_missing_choices_is_rejected(self, stub_server):
        stub_server.script = [{"status": 200, "body": {"model": "m"}}]
        provider = OpenAICompatibleProvider(
            model="m", api_key="k", base_url=_base_url(stub_server)
        )
        with pytest.raises(AIProviderError, match="choices"):
            provider.complete(_request())

    def test_error_envelope_is_surfaced(self, stub_server):
        stub_server.script = [{"status": 200, "body": {"error": "bad thing"}}]
        provider = OpenAICompatibleProvider(
            model="m", api_key="k", base_url=_base_url(stub_server)
        )
        with pytest.raises(AIProviderError, match="bad thing"):
            provider.complete(_request())

    def test_http_401_is_not_retried(self, stub_server):
        stub_server.script = [{"status": 401, "body": {"error": {"message": "unauthorized"}}}]
        provider = OpenAICompatibleProvider(
            model="m", api_key="k", base_url=_base_url(stub_server)
        )
        with pytest.raises(AIProviderError, match="401"):
            provider.complete(_request(max_retries=3))
        assert len(stub_server.requests) == 1

    def test_http_500_is_retried(self, stub_server):
        stub_server.script = [
            {"status": 500, "body": {"error": {"message": "boom"}}},
            {"status": 200, "body": _ok_body()},
        ]
        provider = OpenAICompatibleProvider(
            model="m", api_key="k", base_url=_base_url(stub_server)
        )
        # Patch the backoff so the test does not sleep.
        import scapy_ai_analyzer.ai.providers.openai_provider as module

        original = module.time.sleep
        module.time.sleep = lambda _seconds: None
        try:
            response = provider.complete(_request(max_retries=1))
        finally:
            module.time.sleep = original
        assert response.text
        assert len(stub_server.requests) == 2

    def test_http_429_mentions_rate_limit(self, stub_server):
        stub_server.script = [{"status": 429, "body": {"error": {"message": "slow down"}}}]
        provider = OpenAICompatibleProvider(
            model="m", api_key="k", base_url=_base_url(stub_server)
        )
        with pytest.raises(AIProviderError, match="Rate limit"):
            provider.complete(_request(max_retries=0))

    def test_connection_error_is_mapped(self):
        # Nothing is listening on this port.
        provider = OpenAICompatibleProvider(
            model="m", api_key="k", base_url="http://127.0.0.1:1/v1"
        )
        with pytest.raises((AIProviderError, AITimeoutError)):
            provider.complete(_request(max_retries=0))

    def test_api_key_never_appears_in_error_messages(self):
        provider = OpenAICompatibleProvider(
            model="m", api_key="leaky-secret-key", base_url="http://127.0.0.1:1/v1"
        )
        try:
            provider.complete(_request(max_retries=0))
        except (AIProviderError, AITimeoutError) as exc:
            assert "leaky-secret-key" not in str(exc)
        else:  # pragma: no cover - the call is expected to fail
            pytest.fail("expected the request to fail")
