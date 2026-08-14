"""Unit tests for OpenAIProvider — mocked HTTP via `responses`, no real
network calls to OpenAI. Verifies request construction (endpoint, auth
header, payload shape, image embedding) and response parsing/error handling
against realistic mocked payloads modeled on the OpenAI Chat Completions API
docs as of this writing.
"""

import json

import pytest
import requests
import responses

from globwarden.llm.errors import (
    AuthenticationError,
    ProviderAPIError,
    ProviderConnectionError,
    ProviderRefusalError,
    RateLimitError,
)
from globwarden.llm.openai_provider import OpenAIProvider

CHAT_COMPLETIONS_URL = "https://api.openai.com/v1/chat/completions"


def make_provider(**kwargs):
    kwargs.setdefault("api_key", "sk-test-key")
    return OpenAIProvider(**kwargs)


@responses.activate
def test_complete_builds_correct_request_and_parses_response():
    responses.add(
        responses.POST,
        CHAT_COMPLETIONS_URL,
        json={
            "id": "chatcmpl-abc123",
            "object": "chat.completion",
            "model": "gpt-4o-mini",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "hello there"},
                    "finish_reason": "stop",
                }
            ],
        },
        status=200,
    )

    provider = make_provider()
    resp = provider.complete(system_prompt="You are terse.", user_prompt="Say hi")

    assert len(responses.calls) == 1
    req = responses.calls[0].request
    assert req.headers["Authorization"] == "Bearer sk-test-key"
    assert req.headers["Content-Type"] == "application/json"

    body = json.loads(req.body)
    assert body["model"] == "gpt-4o-mini"
    assert body["messages"] == [
        {"role": "system", "content": "You are terse."},
        {"role": "user", "content": "Say hi"},
    ]
    assert "response_format" not in body

    assert resp.text == "hello there"
    assert resp.model == "gpt-4o-mini"
    assert resp.provider == "openai"
    assert resp.raw["id"] == "chatcmpl-abc123"


@responses.activate
def test_json_mode_sets_response_format():
    responses.add(
        responses.POST,
        CHAT_COMPLETIONS_URL,
        json={
            "model": "gpt-4o-mini",
            "choices": [{"message": {"role": "assistant", "content": "{}"}}],
        },
        status=200,
    )
    provider = make_provider()
    provider.complete(system_prompt="sys", user_prompt="user", json_mode=True)

    body = json.loads(responses.calls[0].request.body)
    assert body["response_format"] == {"type": "json_object"}


@responses.activate
def test_images_are_embedded_as_base64_data_uri():
    responses.add(
        responses.POST,
        CHAT_COMPLETIONS_URL,
        json={
            "model": "gpt-4o-mini",
            "choices": [{"message": {"role": "assistant", "content": "saw it"}}],
        },
        status=200,
    )
    provider = make_provider()
    png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
    provider.complete(system_prompt="sys", user_prompt="what is this?", images=[png_bytes])

    body = json.loads(responses.calls[0].request.body)
    user_content = body["messages"][1]["content"]
    assert isinstance(user_content, list)
    assert user_content[0] == {"type": "text", "text": "what is this?"}
    image_part = user_content[1]
    assert image_part["type"] == "image_url"
    assert image_part["image_url"]["url"].startswith("data:image/png;base64,")


@responses.activate
def test_401_raises_authentication_error():
    responses.add(
        responses.POST,
        CHAT_COMPLETIONS_URL,
        json={"error": {"message": "Incorrect API key provided", "type": "invalid_request_error"}},
        status=401,
    )
    provider = make_provider()
    with pytest.raises(AuthenticationError):
        provider.complete(system_prompt="sys", user_prompt="user")


@responses.activate
def test_429_raises_rate_limit_error():
    responses.add(
        responses.POST,
        CHAT_COMPLETIONS_URL,
        json={"error": {"message": "Rate limit reached", "type": "rate_limit_error"}},
        status=429,
    )
    provider = make_provider()
    with pytest.raises(RateLimitError):
        provider.complete(system_prompt="sys", user_prompt="user")


@responses.activate
def test_500_raises_provider_api_error_with_status_code():
    responses.add(
        responses.POST,
        CHAT_COMPLETIONS_URL,
        json={"error": {"message": "Internal server error"}},
        status=500,
    )
    provider = make_provider()
    with pytest.raises(ProviderAPIError) as exc_info:
        provider.complete(system_prompt="sys", user_prompt="user")
    assert exc_info.value.status_code == 500


@responses.activate
def test_connection_failure_raises_provider_connection_error():
    responses.add(
        responses.POST,
        CHAT_COMPLETIONS_URL,
        body=requests.exceptions.ConnectionError("connection refused"),
    )
    provider = make_provider()
    with pytest.raises(ProviderConnectionError):
        provider.complete(system_prompt="sys", user_prompt="user")


@responses.activate
def test_read_timeout_raises_distinct_actionable_message():
    # See anthropic_provider.py's equivalent regression test for the real
    # production incident this class of fix addresses.
    responses.add(
        responses.POST,
        CHAT_COMPLETIONS_URL,
        body=requests.exceptions.ReadTimeout("read timed out"),
    )
    provider = make_provider()
    with pytest.raises(ProviderConnectionError) as exc_info:
        provider.complete(system_prompt="sys", user_prompt="user")
    message = str(exc_info.value)
    assert "did not finish responding" in message
    assert "OPENAI_TIMEOUT" in message


def test_default_timeout_env_var_override(monkeypatch):
    monkeypatch.setenv("OPENAI_TIMEOUT", "45")
    provider = OpenAIProvider(api_key="k")
    assert provider.timeout == 45.0


def test_is_available_true_with_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = OpenAIProvider(api_key="sk-present")
    assert provider.is_available() is True


def test_is_available_false_without_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = OpenAIProvider(api_key=None)
    assert provider.is_available() is False


def test_reads_api_key_from_env(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-from-env")
    provider = OpenAIProvider()
    assert provider.api_key == "sk-from-env"


def test_explicit_api_key_overrides_env(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-from-env")
    provider = OpenAIProvider(api_key="sk-explicit")
    assert provider.api_key == "sk-explicit"


@responses.activate
def test_empty_content_raises_clear_diagnostic_error_not_silent_empty_text():
    # A 200 response with no usable text is always a real problem for this
    # tool -- see anthropic_provider.py's equivalent check/regression for the
    # real production bug this class of fix addresses. finish_reason "length"
    # means the response was truncated before any text was emitted.
    responses.add(
        responses.POST,
        CHAT_COMPLETIONS_URL,
        json={
            "model": "gpt-4o-mini",
            "choices": [{"message": {"role": "assistant", "content": None}, "finish_reason": "length"}],
            "usage": {"completion_tokens": 4096},
        },
        status=200,
    )
    provider = make_provider()
    with pytest.raises(ProviderAPIError) as exc_info:
        provider.complete(system_prompt="sys", user_prompt="user")

    message = str(exc_info.value)
    assert "no usable text content" in message
    assert "length" in message
    assert exc_info.value.status_code == 200


@responses.activate
def test_content_filter_finish_reason_raises_distinct_refusal_error():
    # A policy/safety decline, not a truncated response -- see
    # anthropic_provider.py's equivalent live-confirmed regression.
    responses.add(
        responses.POST,
        CHAT_COMPLETIONS_URL,
        json={
            "model": "gpt-4o-mini",
            "choices": [{"message": {"role": "assistant", "content": None}, "finish_reason": "content_filter"}],
            "usage": {"completion_tokens": 0},
        },
        status=200,
    )
    provider = make_provider()
    with pytest.raises(ProviderRefusalError) as exc_info:
        provider.complete(system_prompt="sys", user_prompt="user")

    assert "content_filter" in str(exc_info.value)
    assert exc_info.value.status_code == 200
