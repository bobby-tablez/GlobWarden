"""Unit tests for the OpenAICompatibleProvider base class, exercised through
its two concrete subclasses (OllamaProvider, LMStudioProvider) — mocked HTTP
via `responses`, no real local server required for these tests.

For a real integration test against an actual local Ollama server, see
test_ollama_integration.py (skipped automatically unless a server is
detected on localhost:11434).
"""

import json

import pytest
import requests
import responses

from globwarden.llm.errors import (
    AuthenticationError,
    ProviderAPIError,
    ProviderConnectionError,
    RateLimitError,
)
from globwarden.llm.lmstudio_provider import LMStudioProvider
from globwarden.llm.ollama_provider import OllamaProvider

OLLAMA_MODELS_URL = "http://localhost:11434/v1/models"
OLLAMA_CHAT_URL = "http://localhost:11434/v1/chat/completions"
LMSTUDIO_MODELS_URL = "http://localhost:1234/v1/models"
LMSTUDIO_CHAT_URL = "http://localhost:1234/v1/chat/completions"


def _chat_response(model="llama3.2", content="hello there"):
    return {
        "id": "chatcmpl-local-1",
        "object": "chat.completion",
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}}],
    }


class TestOllamaProviderDefaults:
    def test_default_base_url_and_model(self, monkeypatch):
        monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)
        monkeypatch.delenv("OLLAMA_MODEL", raising=False)
        provider = OllamaProvider()
        assert provider.name == "ollama"
        assert provider.base_url == "http://localhost:11434/v1"
        assert provider.model == "llama3.2"

    def test_env_var_overrides(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_BASE_URL", "http://remote-box:11434/v1")
        monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:7b")
        provider = OllamaProvider()
        assert provider.base_url == "http://remote-box:11434/v1"
        assert provider.model == "qwen2.5:7b"

    def test_explicit_kwargs_override_env(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_BASE_URL", "http://remote-box:11434/v1")
        provider = OllamaProvider(base_url="http://explicit:11434/v1")
        assert provider.base_url == "http://explicit:11434/v1"


class TestLMStudioProviderDefaults:
    def test_default_base_url(self, monkeypatch):
        monkeypatch.delenv("LMSTUDIO_BASE_URL", raising=False)
        provider = LMStudioProvider()
        assert provider.name == "lmstudio"
        assert provider.base_url == "http://localhost:1234/v1"
        assert provider.model is None  # no fixed default — auto-detected from /v1/models


@responses.activate
def test_complete_with_explicit_model_no_models_lookup():
    responses.add(responses.POST, OLLAMA_CHAT_URL, json=_chat_response(), status=200)
    provider = OllamaProvider(model="llama3.2")
    resp = provider.complete(system_prompt="sys", user_prompt="hi")

    # Only the chat/completions call should have happened — no /models lookup
    # needed since a model was already configured.
    assert len(responses.calls) == 1
    assert responses.calls[0].request.url == OLLAMA_CHAT_URL

    body = json.loads(responses.calls[0].request.body)
    assert body["model"] == "llama3.2"
    assert body["messages"][0] == {"role": "system", "content": "sys"}

    assert resp.text == "hello there"
    assert resp.provider == "ollama"


@responses.activate
def test_no_authorization_header_when_no_api_key():
    responses.add(responses.POST, OLLAMA_CHAT_URL, json=_chat_response(), status=200)
    provider = OllamaProvider(model="llama3.2", api_key=None)
    provider.complete(system_prompt="sys", user_prompt="hi")
    assert "Authorization" not in responses.calls[0].request.headers


@responses.activate
def test_authorization_header_present_when_api_key_given():
    responses.add(responses.POST, LMSTUDIO_CHAT_URL, json=_chat_response(), status=200)
    provider = LMStudioProvider(model="local-model", api_key="lm-studio-key")
    provider.complete(system_prompt="sys", user_prompt="hi")
    assert responses.calls[0].request.headers["Authorization"] == "Bearer lm-studio-key"


@responses.activate
def test_model_auto_detected_from_models_endpoint_when_unset():
    responses.add(
        responses.GET,
        LMSTUDIO_MODELS_URL,
        json={"data": [{"id": "auto-detected-model"}, {"id": "other-model"}], "object": "list"},
        status=200,
    )
    responses.add(
        responses.POST,
        LMSTUDIO_CHAT_URL,
        json=_chat_response(model="auto-detected-model"),
        status=200,
    )

    provider = LMStudioProvider(model=None)
    resp = provider.complete(system_prompt="sys", user_prompt="hi")

    assert len(responses.calls) == 2
    assert responses.calls[0].request.url == LMSTUDIO_MODELS_URL
    body = json.loads(responses.calls[1].request.body)
    assert body["model"] == "auto-detected-model"
    assert resp.model == "auto-detected-model"


@responses.activate
def test_model_auto_detect_failure_raises_connection_error():
    responses.add(responses.GET, LMSTUDIO_MODELS_URL, json={"data": []}, status=200)
    provider = LMStudioProvider(model=None)
    with pytest.raises(ProviderConnectionError):
        provider.complete(system_prompt="sys", user_prompt="hi")


@responses.activate
def test_images_are_embedded_as_data_uri():
    responses.add(responses.POST, OLLAMA_CHAT_URL, json=_chat_response(), status=200)
    provider = OllamaProvider(model="llava")
    png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
    provider.complete(system_prompt="sys", user_prompt="what is this?", images=[png_bytes])

    body = json.loads(responses.calls[0].request.body)
    content = body["messages"][1]["content"]
    assert isinstance(content, list)
    assert content[1]["type"] == "image_url"
    assert content[1]["image_url"]["url"].startswith("data:image/png;base64,")


@responses.activate
def test_401_raises_authentication_error():
    responses.add(responses.POST, OLLAMA_CHAT_URL, json={"error": "unauthorized"}, status=401)
    provider = OllamaProvider(model="llama3.2")
    with pytest.raises(AuthenticationError):
        provider.complete(system_prompt="sys", user_prompt="hi")


@responses.activate
def test_429_raises_rate_limit_error():
    responses.add(responses.POST, OLLAMA_CHAT_URL, json={"error": "rate limited"}, status=429)
    provider = OllamaProvider(model="llama3.2")
    with pytest.raises(RateLimitError):
        provider.complete(system_prompt="sys", user_prompt="hi")


@responses.activate
def test_500_raises_provider_api_error():
    responses.add(responses.POST, OLLAMA_CHAT_URL, json={"error": "server error"}, status=500)
    provider = OllamaProvider(model="llama3.2")
    with pytest.raises(ProviderAPIError):
        provider.complete(system_prompt="sys", user_prompt="hi")


@responses.activate
def test_empty_content_raises_clear_diagnostic_error_not_silent_empty_text():
    # A 200 response with no usable text is always a real problem for this
    # tool -- see anthropic_provider.py's equivalent check/regression for the
    # real production bug this class of fix addresses. A local model hitting
    # its own small max-output/context cap is a realistic way to trigger
    # finish_reason "length" here.
    responses.add(
        responses.POST,
        OLLAMA_CHAT_URL,
        json={
            "model": "llama3.2",
            "choices": [{"message": {"role": "assistant", "content": ""}, "finish_reason": "length"}],
            "usage": {"completion_tokens": 128},
        },
        status=200,
    )
    provider = OllamaProvider(model="llama3.2")
    with pytest.raises(ProviderAPIError) as exc_info:
        provider.complete(system_prompt="sys", user_prompt="hi")

    message = str(exc_info.value)
    assert "no usable text content" in message
    assert "length" in message
    assert exc_info.value.status_code == 200


@responses.activate
def test_is_available_true_when_server_reachable():
    responses.add(responses.GET, OLLAMA_MODELS_URL, json={"data": [{"id": "llama3.2"}]}, status=200)
    provider = OllamaProvider()
    assert provider.is_available() is True


@responses.activate
def test_is_available_false_when_server_returns_error_status():
    responses.add(responses.GET, OLLAMA_MODELS_URL, json={"error": "nope"}, status=500)
    provider = OllamaProvider()
    assert provider.is_available() is False


@responses.activate
def test_is_available_false_when_connection_refused():
    responses.add(responses.GET, OLLAMA_MODELS_URL, body=requests.exceptions.ConnectionError("refused"))
    provider = OllamaProvider()
    # Must not raise — is_available() is documented to never throw.
    assert provider.is_available() is False


def test_is_available_never_raises_even_on_unexpected_error(monkeypatch):
    provider = OllamaProvider()

    def boom(*args, **kwargs):
        raise RuntimeError("something totally unexpected")

    monkeypatch.setattr("globwarden.llm.openai_compatible.requests.get", boom)
    assert provider.is_available() is False


def test_health_timeout_is_short_by_default():
    # The architecture doc requires local-provider preflight checks to not
    # hang the CLI — assert the default health-check timeout stays well
    # under what a human would notice as "the CLI is stuck."
    provider = OllamaProvider()
    assert provider.health_timeout <= 5.0
