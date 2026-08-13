"""Tests for globwarden.llm.registry — the provider factory."""

import pytest

from globwarden.llm.anthropic_provider import AnthropicProvider
from globwarden.llm.gemini_provider import GeminiProvider
from globwarden.llm.lmstudio_provider import LMStudioProvider
from globwarden.llm.ollama_provider import OllamaProvider
from globwarden.llm.openai_provider import OpenAIProvider
from globwarden.llm.registry import get_provider, list_providers


def test_list_providers_returns_all_five_sorted():
    assert list_providers() == ["anthropic", "gemini", "lmstudio", "ollama", "openai"]


@pytest.mark.parametrize(
    "name,expected_cls",
    [
        ("openai", OpenAIProvider),
        ("anthropic", AnthropicProvider),
        ("gemini", GeminiProvider),
        ("ollama", OllamaProvider),
        ("lmstudio", LMStudioProvider),
    ],
)
def test_get_provider_returns_correct_class(name, expected_cls):
    provider = get_provider(name, api_key="dummy")
    assert isinstance(provider, expected_cls)


def test_get_provider_is_case_insensitive_and_strips_whitespace():
    provider = get_provider(" OpenAI ", api_key="dummy")
    assert isinstance(provider, OpenAIProvider)


def test_get_provider_unknown_name_raises_value_error():
    with pytest.raises(ValueError, match="Unknown LLM provider"):
        get_provider("not-a-real-provider")


def test_get_provider_error_message_lists_available_providers():
    with pytest.raises(ValueError, match="openai"):
        get_provider("bogus")


def test_get_provider_forwards_kwargs_to_constructor():
    provider = get_provider("anthropic", api_key="k", model="claude-haiku-4-5")
    assert provider.api_key == "k"
    assert provider.model == "claude-haiku-4-5"


def test_get_provider_forwards_kwargs_for_local_providers():
    provider = get_provider("ollama", base_url="http://custom:9999/v1", model="mistral")
    assert provider.base_url == "http://custom:9999/v1"
    assert provider.model == "mistral"


def test_all_registered_providers_implement_the_interface():
    from globwarden.llm.base import LLMProvider

    for name in list_providers():
        provider = get_provider(name, api_key="dummy")
        assert isinstance(provider, LLMProvider)
        assert isinstance(provider.name, str) and provider.name
        # is_available() must never raise, per the base contract
        assert provider.is_available() in (True, False)
