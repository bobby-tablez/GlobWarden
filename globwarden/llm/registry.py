"""Provider factory. This is the one place that knows about all concrete
provider classes — engine/cli code should go through `get_provider()` rather
than importing a specific provider class directly, so swapping/adding
providers never requires touching call sites.

Adding a 6th OpenAI-compatible provider (e.g. vLLM, LocalAI, LiteLLM proxy):

    class VLLMProvider(OpenAICompatibleProvider):
        name = "vllm"
        default_base_url = "http://localhost:8000/v1"
        default_model = None
        env_base_url_var = "VLLM_BASE_URL"
        env_model_var = "VLLM_MODEL"

Then add one line to _PROVIDERS below: `"vllm": VLLMProvider`. That's it —
`complete()`, `is_available()`, vision payload construction, and error
handling all come from the shared base class.
"""

from __future__ import annotations

from .anthropic_provider import AnthropicProvider
from .base import LLMProvider
from .gemini_provider import GeminiProvider
from .lmstudio_provider import LMStudioProvider
from .ollama_provider import OllamaProvider
from .openai_provider import OpenAIProvider

_PROVIDERS: dict[str, type[LLMProvider]] = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "gemini": GeminiProvider,
    "ollama": OllamaProvider,
    "lmstudio": LMStudioProvider,
}


def list_providers() -> list[str]:
    """Names of every registered provider, e.g. for `--list-providers`."""
    return sorted(_PROVIDERS.keys())


def get_provider(name: str, **kwargs) -> LLMProvider:
    """Factory: instantiate a provider by name.

    API keys/base_urls/models are read from environment variables by
    convention inside each provider's own `__init__` (OPENAI_API_KEY,
    ANTHROPIC_API_KEY, GOOGLE_API_KEY/GEMINI_API_KEY, OLLAMA_BASE_URL, ...).
    Anything passed as a kwarg here (e.g. from a CLI flag like
    `--api-key`/`--model`/`--base-url`) overrides the environment default,
    since it's forwarded straight to the provider's constructor.

    Raises ValueError for an unknown provider name.
    """
    key = name.strip().lower()
    try:
        cls = _PROVIDERS[key]
    except KeyError:
        raise ValueError(f"Unknown LLM provider {name!r}. Available providers: {', '.join(list_providers())}") from None
    return cls(**kwargs)
