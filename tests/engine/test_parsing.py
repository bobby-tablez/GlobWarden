"""Tests for globwarden.engine._parsing.extract_json_object and its recovery
strategies, including the unescaped-quote/backslash repair pass."""

from __future__ import annotations

import pytest

from globwarden.engine._parsing import JSONExtractionError, extract_json_object


class TestBasicParsing:
    def test_clean_json_parses_as_is(self):
        assert extract_json_object('{"a": 1, "b": "two"}') == {"a": 1, "b": "two"}

    def test_empty_response_raises(self):
        with pytest.raises(JSONExtractionError):
            extract_json_object("")

    def test_whitespace_only_response_raises(self):
        with pytest.raises(JSONExtractionError):
            extract_json_object("   \n  ")

    def test_no_json_object_anywhere_raises(self):
        with pytest.raises(JSONExtractionError):
            extract_json_object("I refuse to produce JSON today, sorry!")


class TestFenceAndTrimRecovery:
    def test_recovers_from_json_code_fence(self):
        text = '```json\n{"a": 1}\n```'
        assert extract_json_object(text) == {"a": 1}

    def test_recovers_from_bare_code_fence(self):
        text = '```\n{"a": 1}\n```'
        assert extract_json_object(text) == {"a": 1}

    def test_recovers_leading_and_trailing_prose(self):
        text = 'Sure, here you go:\n{"a": 1}\nHope that helps!'
        assert extract_json_object(text) == {"a": 1}

    def test_recovers_trailing_comma(self):
        text = '{"a": 1, "b": [1, 2, 3,],}'
        assert extract_json_object(text) == {"a": 1, "b": [1, 2, 3]}


class TestUnescapedQuoteRepair:
    """Regression coverage for a real bug: a live scan against a real
    threat-intel blog (via the Anthropic provider) failed with
    `Expecting ',' delimiter: line 1 column 6458` -- the model copied a
    verbatim source code snippet into `example_snippet` per the detection
    prompt's own instructions, and the snippet contained a literal,
    unescaped `"` (a quoted string literal inside the obfuscated PowerShell
    itself), which prematurely closed the JSON string and broke everything
    after it."""

    def test_literal_quote_inside_string_value_is_repaired(self):
        # Reproduces the exact failure shape: a string literal embedded
        # verbatim inside a JSON string value, with its own quotes left
        # unescaped.
        text = '{"example_snippet": "iex (New-Object Net.WebClient).DownloadString("http://x")", "other": "ok"}'
        result = extract_json_object(text)
        assert result["example_snippet"] == 'iex (New-Object Net.WebClient).DownloadString("http://x")'
        assert result["other"] == "ok"

    def test_multiple_literal_quotes_in_one_value_are_repaired(self):
        text = '{"a": "she said "hello" and then "goodbye"", "b": 2}'
        result = extract_json_object(text)
        assert result["a"] == 'she said "hello" and then "goodbye"'
        assert result["b"] == 2

    def test_known_limitation_documented_not_silently_wrong(self):
        # Honest limitation, not a guarantee: if a literal embedded quote is
        # immediately followed by a comma (e.g. "...gal i*x", then invoke
        # it"...), the repair's lookahead can't tell that apart from a real
        # closing quote followed by the next object member -- it isn't
        # solvable with a one-token lookahead, and this project deliberately
        # doesn't attempt full quote-balance backtracking for it. What
        # matters is the failure mode stays safe: a clear JSONExtractionError
        # with the original text attached, never silently wrong/truncated
        # data returned as if it were correct.
        text = '{"a": "run "gal i*x", then invoke it", "b": 2}'
        with pytest.raises(JSONExtractionError):
            extract_json_object(text)

    def test_real_closing_quote_is_not_treated_as_literal(self):
        # Sanity check the repair doesn't over-fire on perfectly valid JSON.
        text = '{"a": "a normal value", "b": ["x", "y"]}'
        assert extract_json_object(text) == {"a": "a normal value", "b": ["x", "y"]}


class TestUnderEscapedBackslashRepair:
    """The generation prompts ask for regex patterns full of backslash
    metacharacters (`\\s`, `\\*`, `\\(`, ...). A model that forgets to
    double the backslash for JSON (writing a literal `\\s` instead of the
    JSON-correct `\\\\s`) produces text `json.loads` rejects as an invalid
    escape sequence -- the same repair pass fixes this too."""

    def test_under_escaped_regex_backslash_is_repaired(self):
        # Raw text as it would actually arrive over the wire: a single
        # backslash before "s", which is not a valid JSON escape.
        text = '{"pattern": "(?i)\\s+invoke-expression", "explanation": "ok"}'
        result = extract_json_object(text)
        assert result["pattern"] == "(?i)\\s+invoke-expression"

    def test_multiple_under_escaped_metacharacters_are_repaired(self):
        text = '{"pattern": "\\(gal\\s+\\*x\\)", "explanation": "ok"}'
        result = extract_json_object(text)
        assert result["pattern"] == "\\(gal\\s+\\*x\\)"

    def test_properly_escaped_backslash_is_left_alone(self):
        # A correctly double-escaped backslash must survive unchanged, not
        # get mangled into four backslashes.
        text = '{"pattern": "(?i)\\\\s+invoke-expression"}'
        result = extract_json_object(text)
        assert result["pattern"] == "(?i)\\s+invoke-expression"

    def test_valid_json_escapes_are_untouched(self):
        text = '{"a": "line one\\nline two", "b": "a\\ttab", "c": "quote: \\""}'
        result = extract_json_object(text)
        assert result["a"] == "line one\nline two"
        assert result["b"] == "a\ttab"
        assert result["c"] == 'quote: "'


class TestRawControlCharacterRepair:
    def test_raw_newline_inside_string_value_is_repaired(self):
        text = '{"a": "line one\nline two"}'
        result = extract_json_object(text)
        assert result["a"] == "line one\nline two"


class TestStillUnrecoverable:
    def test_genuinely_broken_json_still_raises_with_useful_message(self):
        with pytest.raises(JSONExtractionError) as exc_info:
            extract_json_object("{not json at all, just { broken } nonsense")
        assert "Could not parse LLM response as JSON" in str(exc_info.value) or "Could not locate" in str(exc_info.value)
