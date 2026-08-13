"""LM Studio provider — a thin subclass of OpenAICompatibleProvider.

Same pattern as ollama_provider.py. LM Studio's local server also speaks the
OpenAI chat-completions format at /v1/chat/completions.
"""

from __future__ import annotations

from .openai_compatible import OpenAICompatibleProvider


class LMStudioProvider(OpenAICompatibleProvider):
    name = "lmstudio"
    default_base_url = "http://localhost:1234/v1"
    default_model = None  # LM Studio serves whichever model is loaded; auto-detected via /v1/models
    env_base_url_var = "LMSTUDIO_BASE_URL"
    env_model_var = "LMSTUDIO_MODEL"
    env_api_key_var = "LMSTUDIO_API_KEY"  # LM Studio doesn't require one; supported for parity
