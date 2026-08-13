"""Unit tests for GeminiProvider — mocked HTTP via `responses`.

FLAG FOR REVIEW: this is the least independently-verified of the three
cloud providers (see module docstring in gemini_provider.py and the
handoff doc). The request/response shapes here are transcribed from the
Generative Language API's documented format, not exercised against a real
account. Treat these tests as "our code matches our own model of the wire
format," not "verified against a live Gemini endpoint."
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
from globwarden.llm.gemini_provider import GeminiProvider

GENERATE_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"


def make_provider(**kwargs):
    kwargs.setdefault("api_key", "test-google-key")
    return GeminiProvider(**kwargs)


@responses.activate
def test_complete_builds_correct_request_and_parses_response():
    responses.add(
        responses.POST,
        GENERATE_URL,
        json={
            "candidates": [
                {
                    "content": {"parts": [{"text": "hello there"}], "role": "model"},
                    "finishReason": "STOP",
                }
            ],
            "modelVersion": "gemini-2.0-flash",
        },
        status=200,
    )

    provider = make_provider()
    resp = provider.complete(system_prompt="You are terse.", user_prompt="Say hi")

    req = responses.calls[0].request
    assert req.headers["x-goog-api-key"] == "test-google-key"

    body = json.loads(req.body)
    assert body["system_instruction"] == {"parts": [{"text": "You are terse."}]}
    assert body["contents"] == [{"role": "user", "parts": [{"text": "Say hi"}]}]
    assert "generationConfig" not in body

    assert resp.text == "hello there"
    assert resp.model == "gemini-2.0-flash"
    assert resp.provider == "gemini"


@responses.activate
def test_json_mode_sets_response_mime_type():
    responses.add(
        responses.POST,
        GENERATE_URL,
        json={"candidates": [{"content": {"parts": [{"text": "{}"}]}}]},
        status=200,
    )
    provider = make_provider()
    provider.complete(system_prompt="sys", user_prompt="user", json_mode=True)

    body = json.loads(responses.calls[0].request.body)
    assert body["generationConfig"] == {"responseMimeType": "application/json"}


@responses.activate
def test_images_are_embedded_as_inline_data():
    responses.add(
        responses.POST,
        GENERATE_URL,
        json={"candidates": [{"content": {"parts": [{"text": "saw it"}]}}]},
        status=200,
    )
    provider = make_provider()
    png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
    provider.complete(system_prompt="sys", user_prompt="what is this?", images=[png_bytes])

    body = json.loads(responses.calls[0].request.body)
    parts = body["contents"][0]["parts"]
    assert parts[0] == {"text": "what is this?"}
    inline = parts[1]["inline_data"]
    assert inline["mime_type"] == "image/png"
    assert isinstance(inline["data"], str)


@responses.activate
def test_empty_candidates_returns_empty_text_not_crash():
    # e.g. a safety-filtered response with no candidates
    responses.add(responses.POST, GENERATE_URL, json={"candidates": []}, status=200)
    provider = make_provider()
    resp = provider.complete(system_prompt="sys", user_prompt="user")
    assert resp.text == ""


@responses.activate
def test_401_raises_authentication_error():
    responses.add(
        responses.POST,
        GENERATE_URL,
        json={"error": {"code": 401, "message": "API key not valid", "status": "UNAUTHENTICATED"}},
        status=401,
    )
    provider = make_provider()
    with pytest.raises(AuthenticationError):
        provider.complete(system_prompt="sys", user_prompt="user")


@responses.activate
def test_403_also_raises_authentication_error():
    responses.add(
        responses.POST,
        GENERATE_URL,
        json={"error": {"code": 403, "message": "permission denied"}},
        status=403,
    )
    provider = make_provider()
    with pytest.raises(AuthenticationError):
        provider.complete(system_prompt="sys", user_prompt="user")


@responses.activate
def test_429_raises_rate_limit_error():
    responses.add(
        responses.POST,
        GENERATE_URL,
        json={"error": {"code": 429, "message": "quota exceeded"}},
        status=429,
    )
    provider = make_provider()
    with pytest.raises(RateLimitError):
        provider.complete(system_prompt="sys", user_prompt="user")


@responses.activate
def test_500_raises_provider_api_error():
    responses.add(
        responses.POST,
        GENERATE_URL,
        json={"error": {"code": 500, "message": "internal error"}},
        status=500,
    )
    provider = make_provider()
    with pytest.raises(ProviderAPIError):
        provider.complete(system_prompt="sys", user_prompt="user")


@responses.activate
def test_connection_failure_raises_provider_connection_error():
    responses.add(responses.POST, GENERATE_URL, body=requests.exceptions.ConnectionError("refused"))
    provider = make_provider()
    with pytest.raises(ProviderConnectionError):
        provider.complete(system_prompt="sys", user_prompt="user")


def test_is_available_true_with_key():
    provider = GeminiProvider(api_key="present")
    assert provider.is_available() is True


def test_is_available_false_without_key(monkeypatch):
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    provider = GeminiProvider(api_key=None)
    assert provider.is_available() is False


def test_reads_google_api_key_from_env(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_API_KEY", "from-google-env")
    provider = GeminiProvider()
    assert provider.api_key == "from-google-env"


def test_falls_back_to_gemini_api_key_env(monkeypatch):
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "from-gemini-env")
    provider = GeminiProvider()
    assert provider.api_key == "from-gemini-env"
