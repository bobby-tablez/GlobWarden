"""Tests for the shared LLM error hierarchy."""

import pytest

from globwarden.llm.errors import (
    AuthenticationError,
    LLMError,
    ProviderAPIError,
    ProviderConnectionError,
    RateLimitError,
)


@pytest.mark.parametrize(
    "cls",
    [AuthenticationError, RateLimitError, ProviderAPIError, ProviderConnectionError],
)
def test_all_errors_are_llm_errors(cls):
    assert issubclass(cls, LLMError)


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
