"""Tests for the shared LLM error hierarchy."""

import pytest

from globwarden.llm.errors import (
    AuthenticationError,
    LLMError,
    ProviderAPIError,
    ProviderConnectionError,
    ProviderRefusalError,
    RateLimitError,
)


@pytest.mark.parametrize(
    "cls",
    [AuthenticationError, RateLimitError, ProviderAPIError, ProviderConnectionError, ProviderRefusalError],
)
def test_all_errors_are_llm_errors(cls):
    assert issubclass(cls, LLMError)


def test_provider_refusal_error_is_a_provider_api_error():
    # Subclassing (not a sibling) matters: existing broad
    # `except ProviderAPIError` catch sites must keep working unchanged for
    # callers that don't need to distinguish a refusal from any other
    # non-2xx-shaped provider failure.
    assert issubclass(ProviderRefusalError, ProviderAPIError)


def test_provider_api_error_carries_status_and_body():
    err = ProviderAPIError("boom", status_code=500, body="server exploded")
    assert err.status_code == 500
    assert err.body == "server exploded"
    assert "boom" in str(err)


def test_provider_api_error_defaults():
    err = ProviderAPIError("boom")
    assert err.status_code is None
    assert err.body is None


def test_llm_error_is_a_real_exception():
    with pytest.raises(LLMError):
        raise AuthenticationError("nope")
