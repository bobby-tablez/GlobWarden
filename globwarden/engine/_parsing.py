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

# The escape characters JSON actually recognizes after a backslash. Anything
# else following a backslash inside a string is not valid JSON, however
# common it is in regex syntax (`\s`, `\d`, `\*`, `\(`, ...) or plain prose.
_VALID_JSON_ESCAPES = set('"\\/bfnrtu')


def _repair_unescaped_string_content(text: str) -> str:
    """Re-walk `text` as a minimal JSON tokenizer would, and inside a string
    value, escape whatever the raw text got wrong instead of trusting it.

    This exists because `detect.py`'s prompt explicitly asks the model to
    copy a source snippet "verbatim" into a JSON string, and `generate.py`'s
    prompts ask for regex patterns full of backslash metacharacters (`\\s`,
    `\\*`, `\\(`, ...) -- both are exactly the shapes of content most likely
    to contain a literal `"` or a backslash that isn't part of a valid JSON
    escape sequence, either of which breaks `json.loads` outright (the
    literal `"` closes the string early -- everything after it up to the
    next real `"` reads as loose text, so the parser sees whatever comes
    next and fails with something like "Expecting ',' delimiter"; an
    unescaped `\\s` fails as "Invalid \\escape"). Confirmed against a real
    Anthropic response containing a verbatim PowerShell snippet with an
    embedded, unescaped `"http://..."` string literal.

    Two decisions this makes, both inside a string value only (never outside
    one, where `"` legitimately starts/ends a JSON string and `\\` never
    appears bare):

    - A `"` is treated as the real closing quote only if, skipping
      whitespace, the next character is one of `, : } ]` or end-of-input --
      i.e. it's followed by something that actually looks like valid JSON
      continuation. Otherwise it's almost certainly a literal quote from the
      source content and gets escaped in place.
    - A `\\` is passed through unchanged only if followed by one of JSON's
      own recognized escape characters (`" \\ / b f n r t u`); otherwise the
      backslash itself is escaped (`\\` -> `\\\\`), which is exactly the fix
      for an under-escaped regex metacharacter like `\\s` -> `\\\\s`.

    This is a heuristic, not a real JSON grammar -- it can't perfectly
    distinguish a genuine closing quote from a literal one in every
    conceivable case -- but it directly targets the two failure shapes this
    project has actually hit, and is only ever reached as a last resort
    after the exact/fenced/trimmed parses have already failed.
    """
    out: list[str] = []
    in_string = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]

        if not in_string:
            out.append(ch)
            if ch == '"':
                in_string = True
            i += 1
            continue

        if ch == "\\":
            if i + 1 < n and text[i + 1] in _VALID_JSON_ESCAPES:
                out.append(ch)
                out.append(text[i + 1])
                i += 2
                continue
            # Not a recognized JSON escape -- the backslash itself needs
            # escaping (e.g. a regex `\s` must appear as `\\s` in JSON text).
            out.append("\\\\")
            i += 1
            continue

        if ch == '"':
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j >= n or text[j] in ",:}]":
                out.append(ch)
                in_string = False
                i += 1
                continue
            # Not followed by valid JSON continuation -- a literal quote
            # from the source content, not a real string terminator.
            out.append('\\"')
            i += 1
            continue

        if ch in "\n\r\t":
            out.append({"\n": "\\n", "\r": "\\r", "\t": "\\t"}[ch])
            i += 1
            continue

        out.append(ch)
        i += 1

    return "".join(out)


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
    5. Same candidate again, but with `_repair_unescaped_string_content` run
       over it first -- fixes a literal, unescaped `"` or an under-escaped
       `\\` sitting inside a string value (see that function's docstring),
       the most common cause of real, non-trivially-malformed LLM JSON.

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
            except json.JSONDecodeError:
                # Strategy 5: repair unescaped quotes/backslashes inside
                # string values, then retry.
                try:
                    return json.loads(_repair_unescaped_string_content(cleaned))
                except json.JSONDecodeError as exc:
                    raise JSONExtractionError(
                        "Could not parse LLM response as JSON after stripping markdown "
                        "fences, trailing commas, and attempting to repair unescaped "
                        "quotes/backslashes in string content. First 200 chars of "
                        f"response: {raw_text[:200]!r}. Underlying error: {exc}"
                    ) from exc

    raise JSONExtractionError(
        "Could not locate a JSON object ('{...}') anywhere in the LLM response. "
        f"First 200 chars of response: {raw_text[:200]!r}"
    )
