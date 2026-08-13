"""Real integration test against a live local Ollama server.

This is the one test file in tests/llm/ that makes an actual network call —
to localhost only, never to a paid cloud API, which is explicitly allowed
(and encouraged, time permitting) by the architecture doc for local
providers. It is skipped automatically (not failed) when:

  * no Ollama server is reachable at OLLAMA_BASE_URL / localhost:11434, or
  * the configured model (default: llama3.2:1b) hasn't been pulled.

To run it locally: `brew install ollama && ollama serve &` then
`ollama pull llama3.2:1b`, then `pytest tests/llm/test_ollama_integration.py`.
"""

import os

import pytest
import requests

from globwarden.llm.ollama_provider import OllamaProvider

TEST_MODEL = os.environ.get("GLOBWARDEN_TEST_OLLAMA_MODEL", "llama3.2:1b")
BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")


def _ollama_ready_with_model() -> bool:
    try:
        resp = requests.get(f"{BASE_URL}/models", timeout=2.0)
        if not resp.ok:
            return False
        model_ids = {m["id"] for m in resp.json().get("data", [])}
        return TEST_MODEL in model_ids
    except requests.exceptions.RequestException:
        return False


pytestmark = pytest.mark.skipif(
    not _ollama_ready_with_model(),
    reason=(
        f"No reachable Ollama server with model {TEST_MODEL!r} pulled at {BASE_URL}. "
        f"Run `ollama serve` and `ollama pull {TEST_MODEL}` to enable this test."
    ),
)


def test_is_available_true_against_real_server():
    provider = OllamaProvider(model=TEST_MODEL)
    assert provider.is_available() is True


def test_real_completion_round_trip():
    provider = OllamaProvider(model=TEST_MODEL, completion_timeout=60.0)
    resp = provider.complete(
        system_prompt="You are a helpful assistant. Answer in one short sentence.",
        user_prompt="What is 2 + 2? Answer with just the number.",
    )
    assert resp.provider == "ollama"
    assert resp.model  # server reports back some model identifier
    assert isinstance(resp.text, str)
    assert resp.text.strip() != ""
    # Loose assertion — small local models are not perfectly reliable, but a
    # basic arithmetic question should mention "4" somewhere in the answer.
    assert "4" in resp.text


def test_real_json_mode_round_trip():
    provider = OllamaProvider(model=TEST_MODEL, completion_timeout=60.0)
    resp = provider.complete(
        system_prompt="You output only valid JSON, nothing else.",
        user_prompt='Return a JSON object with a single key "ok" set to true.',
        json_mode=True,
    )
    assert resp.text.strip() != ""


def test_real_model_auto_detection():
    # Don't pass model= explicitly — provider should discover it via /v1/models.
    provider = OllamaProvider(model=None, completion_timeout=60.0)
    resolved = provider._resolve_model()
    assert isinstance(resolved, str) and resolved
