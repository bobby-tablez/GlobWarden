"""OpenAI provider — talks to the OpenAI Chat Completions REST API directly
via `requests` rather than the `openai` Python SDK.

Design choice (documented in the handoff): using raw REST keeps GlobWarden's
required dependency set to just `requests` (already needed for ingest/url.py
and the other REST-based providers) instead of pulling in three separate
heavyweight vendor SDKs (`openai`, `anthropic`, `google-genai`) just to make
one HTTP call each. The wire format is simple and stable enough that this is
a reasonable trade for a CLI tool that wants a light `pip install`.
"""

from __future__ import annotations

import base64
import os

import requests

from ._imageutil import sniff_image_mime_type
from .base import LLMProvider, LLMResponse
from .errors import (
    AuthenticationError,
    ProviderAPIError,
    ProviderConnectionError,
    ProviderRefusalError,
    RateLimitError,
)

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"
# A content-rich detection report can genuinely take a while to finish
# generating -- see anthropic_provider.py's equivalent constant/note for the
# real, confirmed-live incident (a tight timeout paired with a raised
# max_tokens) this margin is sized against. OPENAI_TIMEOUT is the escape
# hatch for anyone who needs to push it higher still.
DEFAULT_TIMEOUT = 180.0


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float | None = None,
    ):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout or float(os.environ.get("OPENAI_TIMEOUT", DEFAULT_TIMEOUT))

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _build_user_content(self, user_prompt: str, images: list[bytes] | None):
        if not images:
            return user_prompt
        parts: list[dict] = [{"type": "text", "text": user_prompt}]
        for img in images:
            mime = sniff_image_mime_type(img)
            b64 = base64.b64encode(img).decode("ascii")
            parts.append(
                {
                    "type": "image_url",
                    "image_url": {"url": f"data:{mime};base64,{b64}"},
                }
            )
        return parts

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        images: list[bytes] | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        payload: dict = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": self._build_user_content(user_prompt, images)},
            ],
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        try:
            resp = requests.post(
                f"{self.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
                timeout=self.timeout,
            )
        except requests.exceptions.Timeout as e:
            # Distinct from "couldn't reach the host at all" -- see
            # anthropic_provider.py's equivalent check for why this gets its
            # own message (different remediation: raise the timeout, not
            # assume a network problem).
            raise ProviderConnectionError(
                f"OpenAI did not finish responding within {self.timeout:.0f}s: {e}. "
                "A content-rich report can genuinely take a while to finish "
                "generating -- raise the timeout via OPENAI_TIMEOUT if this keeps "
                "happening."
            ) from e
        except requests.exceptions.RequestException as e:
            raise ProviderConnectionError(f"Could not reach OpenAI API: {e}") from e

        self._raise_for_status(resp)

        data = resp.json()
        choice = data["choices"][0]
        text = choice["message"].get("content") or ""

        if not text:
            # See anthropic_provider.py's equivalent check for why this
            # matters: a 200 response with no usable text is always a real
            # problem here, and finish_reason is the one piece of context
            # that actually explains why (e.g. "length" means truncated).
            finish_reason = choice.get("finish_reason")
            usage = data.get("usage", {})

            if finish_reason == "content_filter":
                # A policy/safety decline, not a truncated response -- see
                # anthropic_provider.py's equivalent check and
                # ProviderRefusalError's docstring. Content-specific, not
                # systemic, so callers generating per-item content can treat
                # this as "no result for this one item" rather than aborting
                # an entire batch.
                raise ProviderRefusalError(
                    "OpenAI declined to generate content for this request "
                    f"(finish_reason='content_filter', usage={usage!r}). This is a "
                    "policy/safety decision, not a truncated or malformed response.",
                    status_code=resp.status_code,
                    body=str(data)[:2000],
                )

            raise ProviderAPIError(
                "OpenAI returned a 200 response with no usable text content "
                f"(finish_reason={finish_reason!r}, usage={usage!r}). If "
                "finish_reason is 'length', the response was cut off before any "
                "text was emitted; otherwise re-run with --verbose and check the "
                "raw response.",
                status_code=resp.status_code,
                body=str(data)[:2000],
            )

        return LLMResponse(
            text=text,
            model=data.get("model", self.model),
            provider=self.name,
            raw=data,
        )

    def _raise_for_status(self, resp: requests.Response) -> None:
        if resp.status_code == 401:
            raise AuthenticationError("OpenAI rejected the API key (401 Unauthorized).")
        if resp.status_code == 429:
            raise RateLimitError("OpenAI rate-limited this request (429).")
        if not resp.ok:
            body = resp.text[:2000]
            raise ProviderAPIError(
                f"OpenAI API returned {resp.status_code}: {body}",
                status_code=resp.status_code,
                body=body,
            )

    def is_available(self) -> bool:
        try:
            return bool(self.api_key)
        except Exception:
            return False
