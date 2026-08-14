"""Google Gemini provider — talks to the Generative Language API directly via
`requests` rather than the `google-genai` SDK.

See `openai_provider.py`'s module docstring for the "why raw REST" rationale.

Endpoint shape and defaults here are believed correct as of this writing but
are the least independently-verified of the three cloud providers in this
codebase — see the handoff doc for what to double-check against a live
account before trusting this in production.
"""

from __future__ import annotations

import base64
import os

import requests

from ._imageutil import sniff_image_mime_type
from .base import LLMProvider, LLMResponse
from .errors import AuthenticationError, ProviderAPIError, ProviderConnectionError, RateLimitError

DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_MODEL = "gemini-2.0-flash"


class GeminiProvider(LLMProvider):
    name = "gemini"

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 60.0,
    ):
        # GOOGLE_API_KEY is the primary convention; GEMINI_API_KEY is a common
        # alternative other tools in this space also accept — try both.
        self.api_key = api_key or os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        self.model = model or os.environ.get("GEMINI_MODEL", DEFAULT_MODEL)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _headers(self) -> dict:
        return {
            "x-goog-api-key": self.api_key or "",
            "Content-Type": "application/json",
        }

    def _build_parts(self, user_prompt: str, images: list[bytes] | None) -> list[dict]:
        parts: list[dict] = [{"text": user_prompt}]
        for img in images or []:
            mime = sniff_image_mime_type(img)
            b64 = base64.b64encode(img).decode("ascii")
            parts.append({"inline_data": {"mime_type": mime, "data": b64}})
        return parts

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        images: list[bytes] | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        payload: dict = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": self._build_parts(user_prompt, images)}],
        }
        if json_mode:
            payload["generationConfig"] = {"responseMimeType": "application/json"}

        url = f"{self.base_url}/models/{self.model}:generateContent"
        try:
            resp = requests.post(url, headers=self._headers(), json=payload, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            raise ProviderConnectionError(f"Could not reach Gemini API: {e}") from e

        self._raise_for_status(resp)

        data = resp.json()
        text = ""
        candidates = data.get("candidates") or []
        if candidates:
            content_parts = candidates[0].get("content", {}).get("parts", [])
            text = "".join(p.get("text", "") for p in content_parts)

        if not text:
            # See anthropic_provider.py's equivalent check for why this
            # matters: a 200 response with no usable text is always a real
            # problem here. finishReason explains truncation ("MAX_TOKENS")
            # or a safety block ("SAFETY"/"RECITATION"); promptFeedback can
            # carry a block reason even when there are zero candidates at all.
            finish_reason = candidates[0].get("finishReason") if candidates else None
            prompt_feedback = data.get("promptFeedback")
            raise ProviderAPIError(
                "Gemini returned a 200 response with no usable text content "
                f"(finishReason={finish_reason!r}, promptFeedback={prompt_feedback!r}). "
                "If finishReason is 'MAX_TOKENS', the response was cut off before any "
                "text was emitted; otherwise re-run with --verbose and check the raw "
                "response.",
                status_code=resp.status_code,
                body=str(data)[:2000],
            )

        return LLMResponse(
            text=text,
            model=data.get("modelVersion", self.model),
            provider=self.name,
            raw=data,
        )

    def _raise_for_status(self, resp: requests.Response) -> None:
        if resp.status_code in (401, 403):
            raise AuthenticationError(f"Gemini rejected the API key ({resp.status_code}).")
        if resp.status_code == 429:
            raise RateLimitError("Gemini rate-limited this request (429).")
        if not resp.ok:
            body = resp.text[:2000]
            raise ProviderAPIError(
                f"Gemini API returned {resp.status_code}: {body}",
                status_code=resp.status_code,
                body=body,
            )

    def is_available(self) -> bool:
        try:
            return bool(self.api_key)
        except Exception:
            return False
