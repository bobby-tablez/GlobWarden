"""Defensive JSON extraction from LLM responses.

LLMs — even in "json_mode" — routinely wrap JSON in markdown code fences, add a
leading/trailing sentence, use smart quotes, or leave a trailing comma. This
module tries a short, ordered list of increasingly forgiving recovery strategies
before giving up. It is intentionally shared between `detect.py` and
`generate.py`, since both call an LLM and expect a single JSON object back.
"""

from __future__ import annotations

import json
import re


class JSONExtractionError(ValueError):
    """Raised when no JSON object could be recovered from LLM output at all."""


_CODE_FENCE_RE = re.compile(r"```(?:json|yaml|yml)?\s*\n?(.*?)```", re.DOTALL | re.IGNORECASE)


def extract_json_object(raw_text: str) -> dict:
    """Best-effort parse of a single JSON object out of raw LLM text.

    Recovery strategy, in order:
    1. Parse the text as-is.
    2. Strip a markdown code fence (```json ... ``` or bare ``` ... ```) and parse
       the fenced content.
    3. Take the substring between the first ``{`` and the last ``}`` in the text
       (handles a stray leading/trailing sentence around an otherwise-valid
       object) and parse that.
    4. Same as (3) but additionally strips trailing commas before the closing
       ``}``/``]``, a common small-model mistake.

    Raises `JSONExtractionError` with a specific, actionable message if every
    strategy fails — callers should surface this rather than silently returning
    an empty result or letting a raw `json.JSONDecodeError` traceback escape.
    """
    if not raw_text or not raw_text.strip():
        raise JSONExtractionError("LLM response was empty — nothing to parse as JSON.")

    text = raw_text.strip()

    # Strategy 1: parse as-is.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Strategy 2: strip a markdown code fence.
    fence_match = _CODE_FENCE_RE.search(text)
    if fence_match:
        fenced = fence_match.group(1).strip()
        try:
            return json.loads(fenced)
        except json.JSONDecodeError:
            text_for_brace_search = fenced
    else:
        text_for_brace_search = text

    # Strategy 3: substring between the first '{' and the last '}'.
    start = text_for_brace_search.find("{")
    end = text_for_brace_search.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = text_for_brace_search[start : end + 1]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            # Strategy 4: strip trailing commas before a closing bracket/brace.
            cleaned = re.sub(r",\s*([}\]])", r"\1", candidate)
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError as exc:
                raise JSONExtractionError(
                    "Could not parse LLM response as JSON after stripping markdown "
                    "fences and trailing commas. First 200 chars of response: "
                    f"{raw_text[:200]!r}. Underlying error: {exc}"
                ) from exc

    raise JSONExtractionError(
        "Could not locate a JSON object ('{...}') anywhere in the LLM response. "
        f"First 200 chars of response: {raw_text[:200]!r}"
    )
