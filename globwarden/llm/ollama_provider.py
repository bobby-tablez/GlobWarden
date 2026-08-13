"""Ollama provider — a thin subclass of OpenAICompatibleProvider.

This is the "add a 6th provider in ~5 lines" pattern in action: Ollama
exposes an OpenAI-compatible `/v1/chat/completions` endpoint, so all we
need to supply is the name, default base_url, and env var conventions.
"""

from __future__ import annotations

from .openai_compatible import OpenAICompatibleProvider


class OllamaProvider(OpenAICompatibleProvider):
    name = "ollama"
    default_base_url = "http://localhost:11434/v1"
    default_model = "llama3.2"
    env_base_url_var = "OLLAMA_BASE_URL"
    env_model_var = "OLLAMA_MODEL"
    env_api_key_var = "OLLAMA_API_KEY"  # Ollama doesn't require one; supported for parity
