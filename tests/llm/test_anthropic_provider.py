"""Unit tests for AnthropicProvider — mocked HTTP via `responses`.

Verifies request construction (endpoint, x-api-key/anthropic-version
headers, payload shape, image embedding) and response parsing/error
handling against realistic mocked payloads modeled on the Anthropic
Messages API docs as of this writing.

FLAG FOR REVIEW: the exact wire shape here (x-api-key auth, `system` as a
top-level field, `content` blocks with type "image"/"text", response
`content` as a list of typed blocks) is transcribed from documentation, not
verified against a live Anthropic account in this environment (no API key
available; live cloud calls are out of scope per the architecture doc). If
anything about the Messages API wire format has since changed, these tests
would still pass (they test our own code against our own mock) without
catching a real mismatch — see the handoff doc.
"""

import json

import pytest
import requests
import responses

from globwarden.llm.anthropic_provider import AnthropicProvider
from globwarden.llm.errors import (
    AuthenticationError,
    ProviderAPIError,
    ProviderConnectionError,
    RateLimitError,
)

MESSAGES_URL = "https://api.anthropic.com/v1/messages"


def make_provider(**kwargs):
    kwargs.setdefault("api_key", "sk-ant-test-key")
    return AnthropicProvider(**kwargs)


@responses.activate
def test_complete_builds_correct_request_and_parses_response():
    responses.add(
        responses.POST,
        MESSAGES_URL,
        json={
            "id": "msg_01abc",
            "type": "message",
            "role": "assistant",
            "model": "claude-opus-5",
            "content": [{"type": "text", "text": "hello there"}],
            "stop_reason": "end_turn",
        },
        status=200,
    )

    provider = make_provider()
    resp = provider.complete(system_prompt="You are terse.", user_prompt="Say hi")

    req = responses.calls[0].request
    assert req.headers["x-api-key"] == "sk-ant-test-key"
    assert req.headers["anthropic-version"] == "2023-06-01"
    assert req.headers["content-type"] == "application/json"

    body = json.loads(req.body)
    assert body["model"] == "claude-opus-5"
    assert body["system"] == "You are terse."
    assert body["messages"] == [{"role": "user", "content": "Say hi"}]
    assert "max_tokens" in body  # required field on the Messages API

    assert resp.text == "hello there"
    assert resp.model == "claude-opus-5"
    assert resp.provider == "anthropic"
    assert resp.raw["id"] == "msg_01abc"


@responses.activate
def test_json_mode_hints_via_system_prompt_not_a_wire_param():
    # The Messages API has no native json_mode flag (unlike OpenAI's
    # response_format) — verify our best-effort fallback appends an
    # instruction to `system` rather than inventing a nonexistent parameter.
    responses.add(
        responses.POST,
        MESSAGES_URL,
        json={"model": "claude-opus-5", "content": [{"type": "text", "text": "{}"}]},
        status=200,
    )
    provider = make_provider()
    provider.complete(system_prompt="Extract fields.", user_prompt="data", json_mode=True)

    body = json.loads(responses.calls[0].request.body)
    assert "Extract fields." in body["system"]
    assert "JSON" in body["system"]
    assert "response_format" not in body


@responses.activate
def test_images_are_embedded_as_base64_content_blocks():
    responses.add(
        responses.POST,
        MESSAGES_URL,
        json={"model": "claude-opus-5", "content": [{"type": "text", "text": "saw it"}]},
        status=200,
    )
    provider = make_provider()
    png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
    provider.complete(system_prompt="sys", user_prompt="what is this?", images=[png_bytes])

    body = json.loads(responses.calls[0].request.body)
    user_content = body["messages"][0]["content"]
    assert isinstance(user_content, list)
    image_block = user_content[0]
    assert image_block["type"] == "image"
    assert image_block["source"]["type"] == "base64"
    assert image_block["source"]["media_type"] == "image/png"
    text_block = user_content[1]
    assert text_block == {"type": "text", "text": "what is this?"}


@responses.activate
def test_multiple_text_blocks_are_concatenated():
    responses.add(
        responses.POST,
        MESSAGES_URL,
        json={
            "model": "claude-opus-5",
            "content": [
                {"type": "text", "text": "part one. "},
                {"type": "text", "text": "part two."},
            ],
        },
        status=200,
    )
    provider = make_provider()
    resp = provider.complete(system_prompt="sys", user_prompt="user")
    assert resp.text == "part one. part two."


@responses.activate
def test_401_raises_authentication_error():
    responses.add(
        responses.POST,
        MESSAGES_URL,
        json={
            "type": "error",
            "error": {"type": "authentication_error", "message": "invalid x-api-key"},
        },
        status=401,
    )
    provider = make_provider()
    with pytest.raises(AuthenticationError):
        provider.complete(system_prompt="sys", user_prompt="user")


@responses.activate
def test_429_raises_rate_limit_error():
    responses.add(
        responses.POST,
        MESSAGES_URL,
        json={"type": "error", "error": {"type": "rate_limit_error", "message": "rate limited"}},
        status=429,
    )
    provider = make_provider()
    with pytest.raises(RateLimitError):
        provider.complete(system_prompt="sys", user_prompt="user")


@responses.activate
def test_529_overloaded_raises_provider_api_error():
    responses.add(
        responses.POST,
        MESSAGES_URL,
        json={"type": "error", "error": {"type": "overloaded_error", "message": "overloaded"}},
        status=529,
    )
    provider = make_provider()
    with pytest.raises(ProviderAPIError) as exc_info:
        provider.complete(system_prompt="sys", user_prompt="user")
    assert exc_info.value.status_code == 529


@responses.activate
def test_connection_failure_raises_provider_connection_error():
    responses.add(responses.POST, MESSAGES_URL, body=requests.exceptions.ConnectionError("refused"))
    provider = make_provider()
    with pytest.raises(ProviderConnectionError):
        provider.complete(system_prompt="sys", user_prompt="user")


def test_is_available_true_with_key():
    provider = AnthropicProvider(api_key="sk-ant-present")
    assert provider.is_available() is True


def test_is_available_false_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    provider = AnthropicProvider(api_key=None)
    assert provider.is_available() is False


def test_reads_api_key_and_model_from_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-env")
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-haiku-4-5")
    provider = AnthropicProvider()
    assert provider.api_key == "sk-ant-env"
    assert provider.model == "claude-haiku-4-5"


def test_default_model_is_claude_opus_5(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_MODEL", raising=False)
    provider = AnthropicProvider(api_key="k")
    assert provider.model == "claude-opus-5"
