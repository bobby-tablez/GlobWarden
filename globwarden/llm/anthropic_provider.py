"""Anthropic (Claude) provider — talks to the Messages API directly via
`requests` rather than the `anthropic` Python SDK.

See `openai_provider.py`'s module docstring for the rationale (zero extra
required dependency beyond `requests`).

Model default: `claude-opus-5`. This is deliberately the top-tier model
rather than a cheaper one — cost/quality tradeoffs are the operator's call,
not baked into the tool, so override via the `model=` constructor kwarg, the
`--model` CLI flag (wired up by the registry), or the `ANTHROPIC_MODEL`
env var if you want a cheaper/faster model (e.g. `claude-haiku-4-5`).

`max_tokens` note: unlike OpenAI/Gemini, the Messages API requires this as a
mandatory field -- there's no "just let the model decide" option, so this
provider has to pick a real number. Confirmed live: the original default
(4096) was tight enough that a real scan against a content-rich report (many
distinct findings, each with a full description and a base64-encoded verbatim
snippet) hit it, the response got cut off before any `text`-type content
block was ever emitted, and the caller saw a bare "response was empty" error
with no indication why. Raised the default and, since there's no way to pick
one number that's right for every report, added `ANTHROPIC_MAX_TOKENS` as an
env var escape hatch (matching the existing `ANTHROPIC_MODEL` pattern) for
anyone who needs to push it higher still.

`timeout` note: raising max_tokens 4x (above) has a direct, confirmed-live
side effect -- claude-opus-5 generating up to 4x more output before it's
done takes proportionally longer to stream back, and the original 60s
default (a reasonable number for the old, tighter max_tokens) started timing
out on real content-rich reports as a result. Raised in step with the
max_tokens change, with `ANTHROPIC_TIMEOUT` as the matching env var escape
hatch.

`thinking` note: claude-opus-5 performs extended thinking by default -- not
something this provider ever opted into. Confirmed live: on a content-rich
real-world report, the model spent its *entire* max_tokens budget thinking
(content block types=['thinking'], stop_reason='max_tokens', zero text
blocks) and never got to emit the actual JSON answer at all, no matter how
generous max_tokens was raised, since thinking has no built-in cap of its
own. GlobWarden always wants a deterministic structured-JSON answer, never a
reasoning transcript (which isn't parsed or surfaced anywhere), so thinking
is explicitly disabled on every request -- confirmed live this makes the
exact same request return real `text` content immediately instead.
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

DEFAULT_BASE_URL = "https://api.anthropic.com/v1"
DEFAULT_MODEL = "claude-opus-5"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MAX_TOKENS = 16_000
DEFAULT_TIMEOUT = 300.0


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float | None = None,
        max_tokens: int | None = None,
    ):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model or os.environ.get("ANTHROPIC_MODEL", DEFAULT_MODEL)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout or float(os.environ.get("ANTHROPIC_TIMEOUT", DEFAULT_TIMEOUT))
        self.max_tokens = max_tokens or int(os.environ.get("ANTHROPIC_MAX_TOKENS", DEFAULT_MAX_TOKENS))

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
            # See module docstring's `thinking` note: some Claude models think
            # by default, and that thinking has no cap of its own -- it can
            # (confirmed live) consume the entire max_tokens budget on a
            # content-rich report and leave nothing for the actual answer.
            # GlobWarden always wants a deterministic JSON answer, never a
            # reasoning transcript, so thinking is always turned off.
            "thinking": {"type": "disabled"},
        }

        try:
            resp = requests.post(
                f"{self.base_url}/messages",
                headers=self._headers(),
                json=payload,
                timeout=self.timeout,
            )
        except requests.exceptions.Timeout as e:
            # A distinct case from "couldn't reach the host at all" -- the
            # request went out fine, the model just didn't finish (or the
            # response didn't finish streaming back) within `self.timeout`
            # seconds. Confirmed live: this is a real, expected outcome for
            # a genuinely large max_tokens on a content-rich report, not
            # necessarily a network problem -- the remediation is different
            # (raise the timeout), so it gets its own message.
            raise ProviderConnectionError(
                f"Anthropic did not finish responding within {self.timeout:.0f}s: {e}. "
                "A high max_tokens value (see ANTHROPIC_MAX_TOKENS) on a content-rich "
                "report can genuinely take a while to finish generating -- raise the "
                "timeout via ANTHROPIC_TIMEOUT if this keeps happening, rather than "
                "assuming it's a network problem."
            ) from e
        except requests.exceptions.RequestException as e:
            raise ProviderConnectionError(f"Could not reach Anthropic API: {e}") from e

        self._raise_for_status(resp)

        data = resp.json()
        content_blocks = data.get("content", [])
        text_parts = [block.get("text", "") for block in content_blocks if block.get("type") == "text"]
        text = "".join(text_parts)

        if not text:
            # A 200 response with no usable text is always a real problem for
            # this tool (every call site expects to run json.loads on the
            # result) -- surface exactly why now, with the diagnostic detail
            # to actually explain it, rather than letting a bare empty string
            # travel three layers up to a generic "response was empty" error.
            stop_reason = data.get("stop_reason")
            block_types = [block.get("type") for block in content_blocks]
            usage = data.get("usage", {})

            if stop_reason == "refusal":
                # A distinct case from truncation: the model explicitly
                # declined to answer this specific request (a policy/safety
                # refusal), not a response that got cut off. "Raise
                # max_tokens" is actively wrong advice here -- no amount of
                # budget fixes a refusal. Content-specific, not systemic (see
                # ProviderRefusalError docstring): a caller generating
                # per-item content (e.g. one finding among many) can
                # typically treat this as "no result for this one item"
                # rather than aborting an entire batch over it.
                raise ProviderRefusalError(
                    "Anthropic declined to generate content for this request "
                    f"(stop_reason='refusal', usage={usage!r}). This is a policy/safety "
                    "decision by the model, not a truncated or malformed response -- "
                    "raising max_tokens will not help. If this keeps happening for the "
                    "same content, try a different model via --model.",
                    status_code=resp.status_code,
                    body=str(data)[:2000],
                )

            raise ProviderAPIError(
                "Anthropic returned a 200 response with no usable text content "
                f"(stop_reason={stop_reason!r}, content block types={block_types!r}, "
                f"usage={usage!r}, max_tokens={self.max_tokens}). This almost always "
                "means the response was cut off before any text was emitted -- if "
                "stop_reason is 'max_tokens', raise the ANTHROPIC_MAX_TOKENS env var; "
                "otherwise re-run with --verbose and check the raw response.",
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
