"""LLM provider abstraction layer.

`from globwarden.llm import get_provider, list_providers, LLMProvider, LLMResponse`
covers the vast majority of what callers outside this package need.
"""

from .base import LLMProvider, LLMResponse
from .errors import (
    AuthenticationError,
    LLMError,
    ProviderAPIError,
    ProviderConnectionError,
    RateLimitError,
)
from .registry import get_provider, list_providers

__all__ = [
    "LLMProvider",
    "LLMResponse",
    "LLMError",
    "AuthenticationError",
    "RateLimitError",
    "ProviderAPIError",
    "ProviderConnectionError",
    "get_provider",
    "list_providers",
]
