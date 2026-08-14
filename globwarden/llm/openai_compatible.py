"""Shared base for any provider that speaks the OpenAI chat-completions wire
format against a custom `base_url` — this is what Ollama and LM Studio both
do locally, and it's also the shape most self-hosted/local-LLM servers
(vLLM, LocalAI, text-generation-webui's OpenAI-compatible mode, etc.) expose.

Subclass and set `name`, `default_base_url`, and (optionally) the env var
names and a default model. See `ollama_provider.py` / `lmstudio_provider.py`
for the ~5-line shape this makes possible, and the module docstring there
for a worked "adding a 6th provider" example.
"""

from __future__ import annotations

import base64
import os

import requests

from ._imageutil import sniff_image_mime_type
from .base import LLMProvider, LLMResponse
from .errors import AuthenticationError, ProviderAPIError, ProviderConnectionError, RateLimitError


class OpenAICompatibleProvider(LLMProvider):
    """Base class — do not instantiate directly. Subclasses must set at
    least `name` and `default_base_url`."""

    name = "openai_compatible"
    default_base_url = "http://localhost:0/v1"
    default_model: str | None = None
    # Env vars checked for base_url/model/api_key if not passed explicitly.
    # Subclasses override these to give each provider its own convention
    # (e.g. OLLAMA_BASE_URL vs LMSTUDIO_BASE_URL).
    env_base_url_var: str | None = None
    env_model_var: str | None = None
    env_api_key_var: str | None = None

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        health_timeout: float = 2.0,
        completion_timeout: float = 120.0,
    ):
        resolved_base_url = (
            base_url or (os.environ.get(self.env_base_url_var) if self.env_base_url_var else None) or self.default_base_url
        )
        self.base_url = resolved_base_url.rstrip("/")
        self.model = model or (os.environ.get(self.env_model_var) if self.env_model_var else None) or self.default_model
        self.api_key = api_key or (os.environ.get(self.env_api_key_var) if self.env_api_key_var else None)
        # Local servers should respond near-instantly to a health check —
        # keep this short so `is_available()`/`--list-providers` never hangs
        # the CLI waiting on a server that isn't running.
        self.health_timeout = health_timeout
        self.completion_timeout = completion_timeout

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _build_user_content(self, user_prompt: str, images: list[bytes] | None):
        if not images:
            return user_prompt
        parts: list[dict] = [{"type": "text", "text": user_prompt}]
        for img in images:
            mime = sniff_image_mime_type(img)
            b64 = base64.b64encode(img).decode("ascii")
            parts.append({"type": "image_url", "image_url": {"url": f"data:{mime};base64,{b64}"}})
        return parts

    def _resolve_model(self) -> str:
        """If no model was configured, ask the server for its first
        available model. Local servers (Ollama/LM Studio) usually only have
        one model loaded, so this is a reasonable zero-config default."""
        if self.model:
            return self.model
        try:
            resp = requests.get(f"{self.base_url}/models", headers=self._headers(), timeout=self.health_timeout)
            resp.raise_for_status()
            models = resp.json().get("data", [])
            if models:
                return models[0]["id"]
        except requests.exceptions.RequestException:
            pass
        raise ProviderConnectionError(
            f"No model configured for {self.name!r} and none could be auto-detected "
            f"from {self.base_url}/models. Pass model= explicitly or start a model "
            f"on the server."
        )

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        images: list[bytes] | None = None,
        json_mode: bool = False,
    ) -> LLMResponse:
        model = self._resolve_model()
        payload: dict = {
            "model": model,
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
                timeout=self.completion_timeout,
            )
        except requests.exceptions.RequestException as e:
            raise ProviderConnectionError(f"Could not reach {self.name} server at {self.base_url}: {e}") from e

        self._raise_for_status(resp)

        data = resp.json()
        choice = data["choices"][0]
        text = choice["message"].get("content") or ""

        if not text:
            # See anthropic_provider.py's equivalent check for why this
            # matters: a 200 response with no usable text is always a real
            # problem here, and finish_reason is the one piece of context
            # that actually explains why (e.g. "length" means truncated --
            # more likely for a local model with a small context/output cap
            # than for a cloud provider).
            finish_reason = choice.get("finish_reason")
            usage = data.get("usage", {})
            raise ProviderAPIError(
                f"{self.name} returned a 200 response with no usable text content "
                f"(finish_reason={finish_reason!r}, usage={usage!r}). If "
                "finish_reason is 'length', the response was cut off before any "
                "text was emitted -- try a model/server with a larger max output, "
                "or re-run with --verbose and check the raw response.",
                status_code=resp.status_code,
                body=str(data)[:2000],
            )

        return LLMResponse(
            text=text,
            model=data.get("model", model),
            provider=self.name,
            raw=data,
        )

    def _raise_for_status(self, resp: requests.Response) -> None:
        if resp.status_code == 401:
            raise AuthenticationError(f"{self.name} server rejected the request (401).")
        if resp.status_code == 429:
            raise RateLimitError(f"{self.name} server rate-limited this request (429).")
        if not resp.ok:
            body = resp.text[:2000]
            raise ProviderAPIError(
                f"{self.name} server returned {resp.status_code}: {body}",
                status_code=resp.status_code,
                body=body,
            )

    def is_available(self) -> bool:
        """Cheap reachability check: can we hit the server's /models endpoint
        within a short timeout? Never raises — returns False on any failure
        (connection refused, timeout, non-2xx, etc.)."""
        try:
            resp = requests.get(f"{self.base_url}/models", headers=self._headers(), timeout=self.health_timeout)
            return resp.ok
        except requests.exceptions.RequestException:
            return False
        except Exception:
            return False
