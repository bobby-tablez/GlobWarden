"""Anthropic (Claude) provider — talks to the Messages API directly via
`requests` rather than the `anthropic` Python SDK.

See `openai_provider.py`'s module docstring for the rationale (zero extra
required dependency beyond `requests`).

Model default: `claude-opus-5`. This is deliberately the top-tier model
rather than a cheaper one — cost/quality tradeoffs are the operator's call,
not baked into the tool, so override via the `model=` constructor kwarg, the
`--model` CLI flag (wired up by the registry), or the `ANTHROPIC_MODEL`
env var if you want a cheaper/faster model (e.g. `claude-haiku-4-5`).
"""

from __future__ import annotations

import base64
import os

import requests

from ._imageutil import sniff_image_mime_type
from .base import LLMProvider, LLMResponse
from .errors import AuthenticationError, ProviderAPIError, ProviderConnectionError, RateLimitError

DEFAULT_BASE_URL = "https://api.anthropic.com/v1"
DEFAULT_MODEL = "claude-opus-5"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MAX_TOKENS = 4096


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 60.0,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model or os.environ.get("ANTHROPIC_MODEL", DEFAULT_MODEL)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_tokens = max_tokens

    def _headers(self) -> dict:
        return {
            "x-api-key": self.api_key or "",
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }

    def _build_user_content(self, user_prompt: str, images: list[bytes] | None):
        if not images:
            return user_prompt
        parts: list[dict] = []
        for img in images:
            mime = sniff_image_mime_type(img)
            b64 = base64.b64encode(img).decode("ascii")
            parts.append(
                {
                    "type": "image",
                    "source": {"type": "base64", "media_type": mime, "data": b64},
                }
            )
        parts.append({"type": "text", "text": user_prompt})
        return parts

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        images: list[bytes] | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        # The Messages API has no native json_mode flag (unlike OpenAI's
        # response_format). Best-effort hint via the system prompt instead —
        # this is exactly the "not all providers honor json_mode reliably"
        # case the base interface's docstring calls out.
        system = system_prompt
        if json_mode:
            system = (
                system_prompt + "\n\nRespond with valid JSON only. Do not include any explanatory "
                "text, markdown code fences, or commentary outside the JSON object."
            )

        payload: dict = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": [
                {"role": "user", "content": self._build_user_content(user_prompt, images)},
            ],
        }

        try:
            resp = requests.post(
                f"{self.base_url}/messages",
                headers=self._headers(),
                json=payload,
                timeout=self.timeout,
            )
        except requests.exceptions.RequestException as e:
            raise ProviderConnectionError(f"Could not reach Anthropic API: {e}") from e

        self._raise_for_status(resp)

        data = resp.json()
        text_parts = [block.get("text", "") for block in data.get("content", []) if block.get("type") == "text"]
        text = "".join(text_parts)
        return LLMResponse(
            text=text,
            model=data.get("model", self.model),
            provider=self.name,
            raw=data,
        )

    def _raise_for_status(self, resp: requests.Response) -> None:
        if resp.status_code == 401:
            raise AuthenticationError("Anthropic rejected the API key (401 Unauthorized).")
        if resp.status_code == 429:
            raise RateLimitError("Anthropic rate-limited this request (429).")
        if not resp.ok:
            body = resp.text[:2000]
            raise ProviderAPIError(
                f"Anthropic API returned {resp.status_code}: {body}",
                status_code=resp.status_code,
                body=body,
            )

    def is_available(self) -> bool:
        try:
            return bool(self.api_key)
        except Exception:
            return False
