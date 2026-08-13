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
from .errors import AuthenticationError, ProviderAPIError, ProviderConnectionError, RateLimitError

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 60.0,
    ):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

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
        except requests.exceptions.RequestException as e:
            raise ProviderConnectionError(f"Could not reach OpenAI API: {e}") from e

        self._raise_for_status(resp)

        data = resp.json()
        choice = data["choices"][0]
        text = choice["message"].get("content") or ""
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
