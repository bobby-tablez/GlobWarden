"""Shared exception hierarchy for LLM providers.

Not part of the architecture contract's required shapes, but used internally
by every provider in this package so callers (engine/) get consistent,
catchable errors instead of raw `requests` exceptions or bare dicts.
"""

from __future__ import annotations


class LLMError(Exception):
    """Base class for all LLM provider errors."""


class AuthenticationError(LLMError):
    """Raised on 401/403 — missing, invalid, or unauthorized API key."""


class RateLimitError(LLMError):
    """Raised on 429 — provider is rate-limiting the caller."""


class ProviderAPIError(LLMError):
    """Raised on any other non-2xx response from the provider's API.

    Carries the HTTP status code and (when available) the raw response body
    so callers/log lines can show something actionable.
    """

    def __init__(self, message: str, status_code: int | None = None, body: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class ProviderConnectionError(LLMError):
    """Raised when the provider can't be reached at all (DNS, timeout, refused)."""


class ProviderRefusalError(ProviderAPIError):
    """Raised when the provider explicitly declined to generate content for
    this specific request (a policy/safety refusal), as opposed to a
    truncated or otherwise malformed response.

    This is content-specific, not systemic -- confirmed live, a refusal on
    one finding's rule-generation call has no bearing on whether any other
    finding's independent call will succeed. Callers that fail an entire
    batch on any provider error (appropriate for a systemic problem like a
    bad API key) should treat this subtype differently: typically as "this
    one item didn't get a result," not "abort everything."
    """
